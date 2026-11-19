"""Representations owned by the Cubite API."""

from rest_framework import serializers

from lms.djangoapps.course_home_api.outline.serializers import (
    CourseBlockSerializer, EnrollAlertSerializer, ResumeCourseSerializer,
)


class CourseOutlineSerializer(serializers.Serializer):
    course_blocks = CourseBlockSerializer()
    enroll_alert = EnrollAlertSerializer()
    enrollment_mode = serializers.CharField()
    enable_proctored_exams = serializers.BooleanField()
    has_ended = serializers.BooleanField()
    resume_course = ResumeCourseSerializer()
    is_staff = serializers.BooleanField()
