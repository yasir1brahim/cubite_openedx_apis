"""Staff removal and deactivation of LMS accounts and enrollments."""

from functools import partial
import logging

from django.contrib.auth.models import User
from django.db import transaction
from django.utils.decorators import method_decorator
from edx_rest_framework_extensions.auth.jwt.authentication import JwtAuthentication
from opaque_keys import InvalidKeyError
from opaque_keys.edx.keys import CourseKey
from rest_framework.exceptions import NotFound, ParseError
from rest_framework.permissions import BasePermission
from rest_framework.response import Response
from social_django.models import UserSocialAuth

from common.djangoapps.student.models import CourseAccessRole, CourseEnrollment, UserProfile
from common.djangoapps.student.models.course_enrollment import UnenrollmentNotAllowed
from lms.djangoapps.courseware.models import StudentModule

from .safe_errors import CubiteAPIView, operation_failed
from .studio_client import StudioCleanupUnconfirmed, StudioConfigurationInvalid, confirm_creator_cleanup


logger = logging.getLogger(__name__)
RETENTION_MESSAGE = "Certificate records must be retained. This record cannot be deleted."
DEACTIVATION_MESSAGES = {
    "signing_request_pending": "Support must withdraw the pending signing request before deactivation.",
    "certificate_job_active": "A certificate job is still active. Try again after it finishes.",
    "unenrollment_not_allowed": "Open edX does not allow this enrollment to be deactivated.",
}


class ActiveStaff(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user.is_authenticated and request.user.is_active and request.user.is_staff)


@method_decorator(transaction.non_atomic_requests, name="dispatch")
class StaffLifecycleView(CubiteAPIView):
    authentication_classes = (JwtAuthentication,)
    permission_classes = (ActiveStaff,)
    rollback_request_transaction = False

    @staticmethod
    def target_fields(data, fields):
        values = [data.get(field) for field in fields] if hasattr(data, "get") else []
        if not values or any(not isinstance(value, str) or not value.strip() for value in values):
            raise ParseError("Required identifiers are missing or invalid.")
        return values

    @classmethod
    def enrollment_target(cls, data):
        username, email, course = cls.target_fields(data, ("username", "email", "course_id"))
        try:
            course_key = CourseKey.from_string(course)
        except InvalidKeyError as exc:
            raise ParseError("The course ID is invalid.") from exc
        try:
            user = User.objects.get(username=username, email=email)
        except User.DoesNotExist as exc:
            raise NotFound("User not found") from exc
        return user, course_key


class DeleteEdxUser(StaffLifecycleView):
    def delete(self, request):
        from lms.djangoapps.docuseal_certificates.retention import has_retained_records

        username, email = self.target_fields(request.data, ("username", "email"))
        try:
            user = User.objects.get(username=username, email=email)
            enrollments = CourseEnrollment.objects.filter(user_id=user.pk)
            if has_retained_records(enrollments.values("pk")):
                return operation_failed("delete_user", None, RETENTION_MESSAGE, field="user_message",
                                        status_code=409, code="certificate_retention_required")
            confirm_creator_cleanup(user, request.headers["Authorization"])

            with transaction.atomic():
                current = User.objects.select_for_update().get(pk=user.pk)
                if (current.username, current.email) != (user.username, user.email):
                    return operation_failed("delete_user", None, "The account changed. Refresh the member details.",
                                            field="user_message", status_code=409, code="target_changed")
                enrollment_ids = list(enrollments.select_for_update().order_by("pk").values_list("pk", flat=True))
                if has_retained_records(enrollment_ids, lock=True):
                    return operation_failed("delete_user", None, RETENTION_MESSAGE, field="user_message",
                                            status_code=409, code="certificate_retention_required")
                enrollments.delete()
                CourseAccessRole.objects.filter(user=current).delete()
                StudentModule.objects.filter(student=current).delete()
                UserSocialAuth.objects.filter(user=current).delete()
                UserProfile.objects.filter(user=current).delete()
                current.delete()
        except User.DoesNotExist:
            return Response({"user_message": "User not exists"}, status=404)
        except StudioConfigurationInvalid as exc:
            return operation_failed("delete_user", exc, "Studio cleanup is unavailable.", field="user_message",
                                    status_code=503, code="studio_configuration_invalid")
        except StudioCleanupUnconfirmed as exc:
            return operation_failed("delete_user", exc, "Studio could not confirm cleanup. Please retry.",
                                    field="user_message", status_code=502, code="studio_cleanup_unconfirmed")
        return Response({"message": "User and related data deleted", "user_id": user.pk})


class DeleteUserEnrollment(StaffLifecycleView):
    def delete(self, request):
        from lms.djangoapps.docuseal_certificates.retention import has_retained_records

        try:
            user, course_key = self.enrollment_target(request.data)
            with transaction.atomic():
                enrollment = CourseEnrollment.objects.select_for_update().get(user=user, course_id=course_key)
                if has_retained_records([enrollment.pk], lock=True):
                    return operation_failed("delete_enrollment", None, RETENTION_MESSAGE,
                                            status_code=409, code="certificate_retention_required")
                enrollment.delete()
        except NotFound:
            return Response({"message": "User not found"}, status=404)
        except CourseEnrollment.DoesNotExist:
            return Response({"message": "User is not enrolled in this course"}, status=404)
        return Response({"message": "User enrollment deleted successfully", "user_id": user.pk,
                         "course_id": str(course_key)})


class DeactivateUserEnrollment(StaffLifecycleView):
    def post(self, request):
        from lms.djangoapps.docuseal_certificates.retention import deactivation_conflict

        try:
            user, course_key = self.enrollment_target(request.data)
            admin_actor_id = request.data.get("admin_actor_id")
            if admin_actor_id is not None and (type(admin_actor_id) is not int or admin_actor_id <= 0):
                raise ParseError("The Admin actor ID is invalid.")
            with transaction.atomic():
                enrollment = CourseEnrollment.objects.select_for_update().get(user=user, course_id=course_key)
                already_inactive = not enrollment.is_active
                if not already_inactive:
                    conflict = deactivation_conflict(enrollment.pk)
                    if conflict:
                        return operation_failed("deactivate_enrollment", None, DEACTIVATION_MESSAGES[conflict],
                                                status_code=409, code=conflict)
                    CourseEnrollment.unenroll(user, course_key)
                    enrollment.refresh_from_db(fields=["is_active"])
                    if enrollment.is_active:
                        raise UnenrollmentNotAllowed("The enrollment remained active")
                    transaction.on_commit(partial(
                        logger.info, "enrollment_deactivated enrollment_id=%s lms_actor_id=%s admin_actor_id=%s",
                        enrollment.pk, request.user.pk, admin_actor_id,
                    ))
        except NotFound:
            return Response({"message": "User not found"}, status=404)
        except CourseEnrollment.DoesNotExist:
            return Response({"message": "User is not enrolled in this course"}, status=404)
        except UnenrollmentNotAllowed as exc:
            code = "unenrollment_not_allowed"
            return operation_failed("deactivate_enrollment", exc, DEACTIVATION_MESSAGES[code],
                                    status_code=409, code=code)
        return Response({"user_id": user.pk, "course_id": str(course_key), "already_inactive": already_inactive})
