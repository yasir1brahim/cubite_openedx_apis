"""Regression checks for behavior recovered from the working NCEC API.

Run with Python's standard library. Execute the real view classes while replacing
Open edX's database/services at their boundaries. Live route and Django-import
checks must also pass in the built Open edX image before release.
"""
import ast
import logging
from pathlib import Path
from types import SimpleNamespace as NS
import secrets
import string
import sys
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "cubite_api/views.py"
COURSE = "course-v1:Test+Course+2026"


class Response:
    def __init__(self, data, status=200):
        self.data, self.status_code = data, status


class Missing(Exception):
    pass


class Key:
    @classmethod
    def from_string(cls, value):
        if not value.startswith("course-v1:"):
            raise Missing(value)
        return value


class Query:
    def __init__(self, manager, rows):
        self.manager, self.rows = manager, rows

    def exists(self):
        return bool(self.rows)

    def first(self):
        return next(iter(self.rows), None)

    def delete(self):
        for row in list(self.rows):
            self.manager.rows.remove(row)

    def __iter__(self):
        return iter(self.rows)


class Manager:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, **kwargs):
        return Query(self, [r for r in self.rows if all(getattr(r, k) == v for k, v in kwargs.items())])

    def get(self, **kwargs):
        rows = self.filter(**kwargs).rows
        if not rows:
            raise Missing()
        return rows[0]


def view(name, **services):
    tree = ast.parse(SOURCE.read_text())
    node = next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name), None)
    if node is None:
        raise AssertionError(f"Required working API view is absent: {name}")
    context = dict(APIView=object, Response=Response, JsonResponse=Response,
                   JwtAuthentication=object, BearerAuthenticationAllowInactiveUser=object,
                   SessionAuthenticationAllowInactiveUser=object, IsAuthenticated=object,
                   IsStaffOrOwner=object, AllowAny=object, InvalidKeyError=Missing,
                   CourseKey=Key, ItemNotFoundError=Missing, BlockStructureNotFound=Missing,
                   logger=logging.getLogger("runtime-api-tests"), secrets=secrets, string=string,
                   status=NS(HTTP_400_BAD_REQUEST=400, HTTP_403_FORBIDDEN=403,
                             HTTP_404_NOT_FOUND=404, HTTP_500_INTERNAL_SERVER_ERROR=500,
                             HTTP_200_OK=200))
    context.update(services)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), "exec"), context)
    return context[name]()


class RuntimeApiTests(unittest.TestCase):
    def test_public_outline_keeps_titles_and_visibility_in_learner_format(self):
        visibility = NS(hide_from_toc=False, visible_to_staff_only=True)
        outline = NS(course_key=COURSE, title="Safety", sections=[
            NS(usage_key="chapter-1", title="Getting started", visibility=visibility, sequences=[
                NS(usage_key="sequence-1", title="First lesson", visibility=visibility)])])
        response = view("GetPublicCourseOutline", get_course_outline=lambda key: outline).get(
            NS(query_params={"course_id": COURSE}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {"course_blocks": {"root": COURSE, "blocks": {
            "id": COURSE, "display_name": "Safety", "type": "course", "children": [{
                "id": "chapter-1", "display_name": "Getting started", "type": "chapter",
                "visibility": {"hide_from_toc": False, "visible_to_staff_only": True},
                "children": [{"id": "sequence-1", "display_name": "First lesson",
                              "type": "sequential", "visibility": {
                                  "hide_from_toc": False, "visible_to_staff_only": True}, "units": []}]}]}}})

    def test_public_outline_rejects_missing_or_invalid_course_before_lookup(self):
        def forbidden_lookup(key):
            self.fail("Invalid input reached course lookup")
        api = view("GetPublicCourseOutline", get_course_outline=forbidden_lookup)
        for params in [{}, {"course_id": "invalid"}]:
            with self.subTest(params=params):
                self.assertEqual(api.get(NS(query_params=params)).status_code, 400)

    def test_enrollment_delete_leaves_other_users_in_same_course(self):
        student = NS(id=7, email="student@example.test", username="student")
        other = NS(id=8, email="other@example.test", username="other")
        mine, theirs = NS(user=student, course_id=COURSE), NS(user=other, course_id=COURSE)
        manager = Manager([mine, theirs])
        mine.delete = lambda: manager.rows.remove(mine)
        api = view("DeleteUserEnrollment", User=NS(objects=Manager([student]), DoesNotExist=Missing),
                   CourseEnrollment=NS(objects=manager, DoesNotExist=Missing))
        request = NS(data={"username": "student", "email": "student@example.test", "course_id": COURSE},
                     user=NS(is_staff=True, is_superuser=False, username="admin"))
        self.assertEqual(api.delete(request).status_code, 200)
        self.assertEqual(manager.rows, [theirs])

    def test_enrollment_delete_validates_input_without_deleting(self):
        manager = Manager([])
        api = view("DeleteUserEnrollment", User=NS(objects=Manager([]), DoesNotExist=Missing),
                   CourseEnrollment=NS(objects=manager, DoesNotExist=Missing))
        response = api.delete(NS(data={}, user=NS(is_staff=True, is_superuser=False, username="admin")))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(manager.rows, [])

    def test_name_update_uses_existing_account_and_preserves_password(self):
        student = NS(id=7, email="student@example.test", username="student", first_name="Old",
                     last_name="Name", password="existing-hash", save=lambda: None)
        profile = NS(user=student, name="Old Name", save=lambda: None)
        models = NS(UserProfile=NS(objects=Manager([profile])))
        api = view("Accounts", User=NS(objects=Manager([student])))
        with patch.dict(sys.modules, {"common.djangoapps.student.models": models}):
            response = api.post(NS(data={"username": "student", "email": "student@example.test", "name": "New Name"}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual((student.first_name, student.last_name, profile.name, student.password),
                         ("New", "Name", "New Name", "existing-hash"))

    def test_subsection_units_keep_both_unit_and_subsection_visibility(self):
        unit = NS(location="unit-1", display_name="Lesson", category="vertical",
                  hide_from_toc=True, visible_to_staff_only=False)
        subsection = NS(hide_from_toc=False, visible_to_staff_only=True, get_children=lambda: [unit])
        api = view("GetCourseOutline", modulestore=lambda: NS(get_item=lambda key: subsection))
        api.get_unit_completion = lambda *args: (0.5, [])
        data = api.get_subsection_units(NS(), COURSE, "sequence-1")
        self.assertEqual(data, [{"id": "unit-1", "display_name": "Lesson", "type": "vertical",
                               "completion": 0.5, "child_blocks": [],
                               "visibility": {"hide_from_toc": True, "visible_to_staff_only": False},
                               "subsection_visibility": {"hide_from_toc": False, "visible_to_staff_only": True}}])

    def test_progress_emits_certificate_signal_only_for_passing_grade(self):
        student = NS(email="student@example.test")
        sent = []
        grade = NS(summary={"grade": "Pass"}, update=lambda **kwargs: None)
        factory = type("Grades", (), {"read": lambda self, *args, **kwargs: grade})
        api = view("ProgressCourseView", User=NS(objects=Manager([student])),
                   CourseEnrollment=NS(objects=Manager([NS(user=student, is_active=True, course_id=COURSE)])),
                   has_access=lambda *args: False,
                   get_block_structure_manager=lambda key: NS(get_collected=lambda: None),
                   CourseGradeFactory=factory,
                   COURSE_GRADE_NOW_PASSED=NS(send=lambda **kwargs: sent.append(kwargs)))
        response = api.get(NS(user=student))
        self.assertEqual(response.data, {"response": [{"grade": "Pass", "course_id": COURSE}]})
        self.assertEqual(sent, [{"sender": factory, "user": student, "course_id": COURSE}])
        sent.clear()
        grade.summary = {"grade": "Fail"}
        api.get(NS(user=student))
        self.assertEqual(sent, [])


if __name__ == "__main__":
    unittest.main()
