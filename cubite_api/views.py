from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from edx_rest_framework_extensions.auth.jwt.authentication import JwtAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from opaque_keys.edx.keys import CourseKey
from opaque_keys import InvalidKeyError
from common.djangoapps.student.models import CourseEnrollment
from openedx.core.djangoapps.enrollments import api as enrollment_api
import logging

logger = logging.getLogger(__name__)

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
    authentication_classes = (JwtAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        # Verify the user has appropriate permissions
        if not (request.user.is_staff or request.user.is_superuser):
            logger.error("User %s does not have sufficient permissions", request.user)
            return Response(
                {"message": "Insufficient permissions"},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate request data exists
        if not request.data:
            logger.error("No data provided in request")
            return Response(
                {"message": "No data provided in request"},
                status=status.HTTP_400_BAD_REQUEST
            )

        email = request.data.get('email')
        course_id = request.data.get('course_id')

        if not email or not course_id:
            logger.error("Missing required fields: email=%s, course_id=%s", email, course_id)
            return Response(
                {
                    "message": "Both email and course_id are required.",
                    "received_data": {
                        "email": email,
                        "course_id": course_id
                    }
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Validate course key format
            course_key = CourseKey.from_string(course_id)
        except InvalidKeyError:
            logger.error("Invalid course ID format: %s", course_id)
            return Response(
                {"message": f"Invalid course ID format: {course_id}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Get user by email
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.error("User with email %s does not exist", email)
            return Response(
                {"message": f"User with email {email} does not exist"},
                status=status.HTTP_404_NOT_FOUND
            )

        try:
            # Check if user is already enrolled
            if CourseEnrollment.is_enrolled(user, course_key):
                logger.info("User %s is already enrolled in course %s", email, course_id)
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
            
            logger.info("Successfully enrolled user %s in course %s", email, course_id)
            return Response({
                "message": "Enrollment successful",
                "enrollment": enrollment
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error("Enrollment error for user %s in course %s: %s", 
                        email, course_id, str(e))
            return Response(
                {
                    "message": "An error occurred during enrollment",
                    "details": str(e)
                },
                status=status.HTTP_400_BAD_REQUEST
            )
