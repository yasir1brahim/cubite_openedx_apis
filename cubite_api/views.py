from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from opaque_keys.edx.keys import CourseKey
from opaque_keys import InvalidKeyError
from common.djangoapps.student.models import CourseEnrollment
from openedx.core.djangoapps.enrollments import api as enrollment_api

class Enrollments(APIView):
    """
    **Use Case**
        Enroll a student in a course using their email address.
        JWT authentication required.

    **Example Request**
        POST /cubite/api/v1/enrollment
        {
            "email": "student@example.com",
            "course_id": "course-v1:edX+DemoX+Demo_Course"
        }
    """
    authentication_classes = (JSONWebTokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        email = request.data.get('email')
        course_id = request.data.get('course_id')

        if not email or not course_id:
            return Response(
                {"message": "Both email and course_id are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Validate course key format
            course_key = CourseKey.from_string(course_id)
        except InvalidKeyError:
            return Response(
                {"message": f"Invalid course ID format: {course_id}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Get user by email
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"message": f"User with email {email} does not exist"},
                status=status.HTTP_404_NOT_FOUND
            )

        try:
            # Check if user is already enrolled
            if CourseEnrollment.is_enrolled(user, course_key):
                return Response(
                    {"message": f"User {email} is already enrolled in course {course_id}"},
                    status=status.HTTP_200_OK
                )

            # Enroll the user
            enrollment = enrollment_api.add_enrollment(
                user.username,
                course_id,
                mode='audit',
                is_active=True
            )
            
            return Response({
                "message": "Enrollment successful",
                "enrollment": enrollment
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {
                    "message": "An error occurred during enrollment",
                    "details": str(e)
                },
                status=status.HTTP_400_BAD_REQUEST
            )
