from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from edx_rest_framework_extensions.auth.jwt.authentication import JwtAuthentication
from rest_framework.permissions import IsAuthenticated
from openedx.core.lib.api.permissions import IsStaffOrOwner
from django.contrib.auth.models import User
from opaque_keys import InvalidKeyError
from common.djangoapps.student.models import CourseEnrollment, CourseAccessRole, UserProfile
from social_django.models import UserSocialAuth
from lms.djangoapps.courseware.models import StudentModule
from openedx.core.djangoapps.enrollments import api as enrollment_api
from django.contrib.auth.models import User

import logging
import random
import string
import secrets

# Outline View Imports
from datetime import datetime, timezone
from functools import cached_property

from completion.exceptions import UnavailableCompletionData  # lint-amnesty, pylint: disable=wrong-import-order
from completion.models import BlockCompletion
from completion.utilities import get_key_to_last_completed_block  # lint-amnesty, pylint: disable=wrong-import-order
from django.conf import settings  # lint-amnesty, pylint: disable=wrong-import-order
from django.core.cache import cache
from django.shortcuts import get_object_or_404  # lint-amnesty, pylint: disable=wrong-import-order
from django.urls import reverse  # lint-amnesty, pylint: disable=wrong-import-order
from django.utils.translation import gettext as _  # lint-amnesty, pylint: disable=wrong-import-order
from edx_django_utils import monitoring as monitoring_utils  # lint-amnesty, pylint: disable=wrong-import-order
from edx_rest_framework_extensions.auth.jwt.authentication import JwtAuthentication  # lint-amnesty, pylint: disable=wrong-import-order
from edx_rest_framework_extensions.auth.session.authentication import SessionAuthenticationAllowInactiveUser  # lint-amnesty, pylint: disable=wrong-import-order
from opaque_keys.edx.keys import CourseKey  # lint-amnesty, pylint: disable=wrong-import-order
from rest_framework.decorators import api_view, authentication_classes, permission_classes  # lint-amnesty, pylint: disable=wrong-import-order
from rest_framework.exceptions import APIException, ParseError  # lint-amnesty, pylint: disable=wrong-import-order
from rest_framework.generics import RetrieveAPIView  # lint-amnesty, pylint: disable=wrong-import-order
from rest_framework.permissions import IsAuthenticated  # lint-amnesty, pylint: disable=wrong-import-order
from rest_framework.response import Response  # lint-amnesty, pylint: disable=wrong-import-order

from common.djangoapps.course_modes.models import CourseMode
from common.djangoapps.util.views import expose_header
from lms.djangoapps.course_goals.api import (
    add_course_goal,
    get_course_goal,
)
from lms.djangoapps.course_goals.models import CourseGoal
from lms.djangoapps.course_home_api.outline.serializers import (
    CourseBlockSerializer,
    OutlineTabSerializer,
)
from lms.djangoapps.course_home_api.utils import get_course_or_403
from lms.djangoapps.courseware.access import has_access
from lms.djangoapps.courseware.context_processor import user_timezone_locale_prefs
from lms.djangoapps.courseware.courses import get_course_date_blocks, get_course_info_section
from lms.djangoapps.courseware.date_summary import TodaysDate
from lms.djangoapps.courseware.masquerade import is_masquerading, setup_masquerade
from lms.djangoapps.courseware.toggles import courseware_disable_navigation_sidebar_blocks_caching
from lms.djangoapps.courseware.views.views import get_cert_data
from lms.djangoapps.grades.course_grade_factory import CourseGradeFactory
from lms.djangoapps.utils import OptimizelyClient
from openedx.core.djangoapps.content.learning_sequences.api import get_user_course_outline
from openedx.core.djangoapps.content.course_overviews.api import get_course_overview_or_404
from openedx.core.djangoapps.course_groups.cohorts import get_cohort
from openedx.core.lib.api.authentication import BearerAuthenticationAllowInactiveUser
from openedx.features.course_duration_limits.access import get_access_expiration_data
from openedx.features.course_experience import COURSE_ENABLE_UNENROLLED_ACCESS_FLAG, ENABLE_COURSE_GOALS
from openedx.features.course_experience.course_tools import CourseToolsPluginManager
from openedx.features.course_experience.course_updates import (
    dismiss_current_update_for_user,
    get_current_update_for_user
)
from openedx.features.course_experience.url_helpers import get_learning_mfe_home_url
from openedx.features.course_experience.utils import get_course_outline_block_tree, get_start_block
from openedx.features.discounts.utils import generate_offer_data
from xblock.core import XBlock
from xblock.completable import XBlockCompletionMode
from xmodule.course_block import COURSE_VISIBILITY_PUBLIC, COURSE_VISIBILITY_PUBLIC_OUTLINE  # lint-amnesty, pylint: disable=wrong-import-order

from openedx.core.djangoapps.user_authn.views.register import create_account_with_params
from django.core.exceptions import NON_FIELD_ERRORS, ValidationError
from django.db import transaction

# Add these imports at the top
from xmodule.modulestore.django import modulestore
from opaque_keys.edx.locator import BlockUsageLocator

# New import statements
from rest_framework.permissions import IsAuthenticated
from common.djangoapps.student.api import is_user_enrolled_in_course
from lms.djangoapps.courseware.courses import get_course_with_access
from lms.djangoapps.instructor.views.tools import get_student_from_identifier
from lms.djangoapps.instructor.access import ROLES, allow_access, revoke_access
from django.utils.html import strip_tags
from edx_rest_framework_extensions.auth.jwt.authentication import JwtAuthentication  # lint-amnesty, pylint: disable=wrong-import-order
from openedx.core.lib.api.authentication import BearerAuthenticationAllowInactiveUser
from openedx.core.djangoapps.content.block_structure.api import get_block_structure_manager
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from django.contrib.auth import logout
from django.http import JsonResponse
from django.http import HttpResponse
from django.shortcuts import redirect

from django.utils.http import urlencode
import re
import bleach
import urllib.parse as parse
from urllib.parse import parse_qs, urlsplit, urlunsplit

from oauth2_provider.models import Application
from openedx.core.djangoapps.safe_sessions.middleware import mark_user_change_as_expected
from openedx.core.djangoapps.user_authn.cookies import delete_logged_in_cookies
from openedx.core.djangoapps.user_authn.utils import is_safe_login_or_logout_redirect
from common.djangoapps.third_party_auth import pipeline as tpa_pipeline
from xmodule.modulestore.exceptions import ItemNotFoundError
from openedx.core.djangoapps.content.block_structure.exceptions import BlockStructureNotFound
import requests

logger = logging.getLogger(__name__)

class Enrollments(APIView):
    """
    **Use Case**
        Enroll a student in a course using their email address.
        JWT authentication required.

    **Example Request**
        POST /lms_custom/api/v1/enrollment
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


class GetUserInfo(APIView):
    authentication_classes = (JwtAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        # search for email in the parameters of the request
        email = request.query_params.get('email')
        if not email:
            return Response({"message": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # get the user info from the email
            user = User.objects.get(email=email)
            return Response({"user_id": user.id, "username": user.username}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"message": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)
        

class GetCourseOutline(APIView):
    """
    API view to get course outline for a specific user.
    Requires staff permissions and accepts course_id and email as query parameters.
    """
    authentication_classes = (
        SessionAuthenticationAllowInactiveUser,
        JwtAuthentication,
        BearerAuthenticationAllowInactiveUser,
    )
    permission_classes = (IsAuthenticated,)

    def get_block_completion(self, user, course_key, block_id):
        """
        Get completion status for a specific block
        """
        try:
            completion = BlockCompletion.objects.get(
                user=user,
                context_key=course_key,  # Changed from course_key to context_key
                block_key=block_id
            )
            return completion.completion
        except BlockCompletion.DoesNotExist:
            return 0.0

    def get_unit_completion(self, user, course_key, unit):
        """
        Calculate unit completion based on its child blocks
        """
        try:
            # Get all child blocks of the unit
            child_blocks = unit.get_children()
            if not child_blocks:
                return 0.0, []

            completable_blocks = []
            for block in child_blocks:
                # Only track completable blocks
                if block.category in ['html', 'video', 'problem', 'drag-and-drop-v2']:
                    completion = self.get_block_completion(user, course_key, block.location)
                    completable_blocks.append({
                        'display_name': block.display_name,
                        'type': block.category,
                        'id': str(block.location),
                        'completion': completion
                    })

            # Calculate overall completion for the unit
            total_blocks = len(completable_blocks)
            if total_blocks > 0:
                completed_blocks = sum(1 for block in completable_blocks if block['completion'] > 0)
                unit_completion = completed_blocks / total_blocks
            else:
                unit_completion = 0.0

            return unit_completion, completable_blocks

        except Exception as e:
            logger.error(f"Error calculating unit completion: {str(e)}")
            return 0.0, []

    def get_subsection_units(self, user, course_key, subsection_id):
        """
        Get all units within a subsection along with their completion status
        """
        store = modulestore()
        units = []
        
        try:
            subsection = store.get_item(subsection_id)
            
            for unit in subsection.get_children():
                completion, child_blocks = self.get_unit_completion(user, course_key, unit)
                unit_data = {
                    'id': str(unit.location),
                    'display_name': unit.display_name,
                    'type': unit.category,
                    'completion': completion,
                    'child_blocks': child_blocks  # Include child blocks in response
                }
                units.append(unit_data)
                
        except Exception as e:
            logger.error(f"Error getting units for subsection {subsection_id}: {str(e)}")
            
        return units

    def get(self, request, *args, **kwargs):
        # Get and validate required parameters
        course_key_string = request.query_params.get('course_id')
        email = request.query_params.get('email')

        if not course_key_string or not email:
            return Response(
                {"message": "Both course_id and email are required parameters"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            course_key = CourseKey.from_string(course_key_string)
        except InvalidKeyError:
            return Response(
                {"message": f"Invalid course ID format: {course_key_string}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            user = request.user

        # Enable NR tracing for this view based on course
        monitoring_utils.set_custom_attribute('course_id', course_key_string)
        monitoring_utils.set_custom_attribute('user_id', user.id)
        monitoring_utils.set_custom_attribute('is_staff', user.is_staff)

        course = get_course_or_403(user, 'load', course_key, check_if_enrolled=False)

        masquerade_object, request.user = setup_masquerade(
            request,
            course_key,
            staff_access=has_access(request.user, 'staff', course_key),
            reset_masquerade_data=True,
        )

        user_is_masquerading = is_masquerading(user, course_key, course_masquerade=masquerade_object)

        course_overview = get_course_overview_or_404(course_key)
        enrollment = CourseEnrollment.get_enrollment(user, course_key)
        print("Enrollment:", enrollment)
        if not enrollment:
            return Response(
                {"message": f"User is not enrolled in: {course_key_string}"},
                status=status.HTTP_404_NOT_FOUND
            )

        enrollment_mode = getattr(enrollment, 'mode', None)
        allow_anonymous = COURSE_ENABLE_UNENROLLED_ACCESS_FLAG.is_enabled(course_key)
        allow_public = allow_anonymous and course.course_visibility == COURSE_VISIBILITY_PUBLIC
        allow_public_outline = allow_anonymous and course.course_visibility == COURSE_VISIBILITY_PUBLIC_OUTLINE

        # User locale settings
        user_timezone_locale = user_timezone_locale_prefs(request)
        user_timezone = user_timezone_locale['user_timezone']

        dates_tab_link = get_learning_mfe_home_url(course_key=course.id, url_fragment='dates')

        # Set all of the defaults
        access_expiration = None
        cert_data = None
        course_blocks = None
        course_goals = {
            'selected_goal': None,
            'weekly_learning_goal_enabled': False,
        }
        course_tools = CourseToolsPluginManager.get_enabled_course_tools(request, course_key)
        dates_widget = {
            'course_date_blocks': [],
            'dates_tab_link': dates_tab_link,
            'user_timezone': user_timezone,
        }
        enroll_alert = {
            'can_enroll': True,
            'extra_text': None,
        }
        handouts_html = None
        offer_data = None
        resume_course = {
            'has_visited_course': False,
            'url': None,
        }
        welcome_message_html = None

        is_enrolled = enrollment and enrollment.is_active
        is_staff = bool(has_access(user, 'staff', course_key))
        show_enrolled = is_enrolled or is_staff
        enable_proctored_exams = False

        if show_enrolled:
            course_blocks = get_course_outline_block_tree(request, course_key_string, user)
            date_blocks = get_course_date_blocks(course, user, request, num_assignments=1)
            dates_widget['course_date_blocks'] = [block for block in date_blocks if not isinstance(block, TodaysDate)]

            handouts_html = get_course_info_section(request, user, course, 'handouts')
            welcome_message_html = get_current_update_for_user(request, course)

            offer_data = generate_offer_data(user, course_overview)
            access_expiration = get_access_expiration_data(user, course_overview)
            cert_data = get_cert_data(user, course, enrollment.mode) if is_enrolled else None

            enable_proctored_exams = course_overview.enable_proctored_exams

            if (is_enrolled and ENABLE_COURSE_GOALS.is_enabled(course_key)):
                course_goals['weekly_learning_goal_enabled'] = True
                selected_goal = get_course_goal(user, course_key)
                if selected_goal:
                    course_goals['selected_goal'] = {
                        'days_per_week': selected_goal.days_per_week,
                        'subscribed_to_reminders': selected_goal.subscribed_to_reminders,
                    }

            try:
                resume_block = get_key_to_last_completed_block(user, course.id)
                resume_course['has_visited_course'] = True
                resume_path = reverse('jump_to', kwargs={
                    'course_id': course_key_string,
                    'location': str(resume_block)
                })
                resume_course['url'] = request.build_absolute_uri(resume_path)
            except UnavailableCompletionData:
                start_block = get_start_block(course_blocks)
                resume_course['url'] = start_block['lms_web_url']

        elif allow_public_outline or allow_public or user_is_masquerading:
            course_blocks = get_course_outline_block_tree(request, course_key_string, None)
            if allow_public or user_is_masquerading:
                handouts_html = get_course_info_section(request, user, course, 'handouts')

        if not is_enrolled:
            if CourseMode.is_masters_only(course_key):
                enroll_alert['can_enroll'] = False
                enroll_alert['extra_text'] = _(
                    'Please contact your degree administrator or '
                    '{platform_name} Support if you have questions.'
                ).format(platform_name=settings.PLATFORM_NAME)
            elif CourseEnrollment.is_enrollment_closed(user, course_overview):
                enroll_alert['can_enroll'] = False
            elif CourseEnrollment.objects.is_course_full(course_overview):
                enroll_alert['can_enroll'] = False
                enroll_alert['extra_text'] = _('Course is full')

        if course_blocks:
            user_course_outline = get_user_course_outline(
                course_key, user, datetime.now(tz=timezone.utc)
            )
            available_seq_ids = {str(usage_key) for usage_key in user_course_outline.sequences}
            available_section_ids = {str(section.usage_key) for section in user_course_outline.sections}

            course_blocks['children'] = [
                chapter_data
                for chapter_data in course_blocks.get('children', [])
                if chapter_data['id'] in available_section_ids
            ]

            for chapter_data in course_blocks['children']:
                chapter_data['children'] = [
                    seq_data
                    for seq_data in chapter_data['children']
                    if (
                        seq_data['id'] in available_seq_ids or
                        seq_data['type'] != 'sequential'
                    )
                ] if 'children' in chapter_data else []

        user_has_passing_grade = False
        if not user.is_anonymous:
            user_grade = CourseGradeFactory().read(user, course)
            if user_grade:
                user_has_passing_grade = user_grade.passed

        data = {
            'access_expiration': access_expiration,
            'cert_data': cert_data,
            'course_blocks': course_blocks,
            'course_goals': course_goals,
            'course_tools': course_tools,
            'dates_widget': dates_widget,
            'enable_proctored_exams': enable_proctored_exams,
            'enroll_alert': enroll_alert,
            'enrollment_mode': enrollment_mode,
            'handouts_html': handouts_html,
            'has_ended': course.has_ended(),
            'offer': offer_data,
            'resume_course': resume_course,
            'user_has_passing_grade': user_has_passing_grade,
            'welcome_message_html': welcome_message_html,
        }

        try:
            serializer = OutlineTabSerializer(
                data,
                context={
                    'course_overview': course_overview,
                    'enable_links': show_enrolled or allow_public,
                    'enrollment': enrollment,
                    'request': request,
                    'view': self
                }
            )
            
            # Get the serialized data
            outline_data = serializer.data
            
            # Add units to each subsection in the course blocks
            if 'course_blocks' in outline_data and 'blocks' in outline_data['course_blocks']:
                blocks = outline_data['course_blocks']['blocks']
                
                for block_key, block_data in blocks.items():
                    if block_data.get('type') == 'sequential':
                        # This is a subsection
                        block_id = BlockUsageLocator.from_string(block_key)
                        units = self.get_subsection_units(user, course_key, block_id)
                        block_data['units'] = units

            return Response(outline_data)

        except Exception as e:
            logger.error(f"Error processing course outline data: {str(e)}", exc_info=True)
            return Response(
                {"message": "Error processing course outline data"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


    def finalize_response(self, request, response, *args, **kwargs):
        """
        Return the final response, exposing the 'Date' header for computing relative time to the dates in the data.

        Important dates such as 'access_expiration' are enforced server-side based on correct time; client-side clocks
        are frequently substantially far off which could lead to inaccurate messaging and incorrect expectations.
        Therefore, any messaging about those dates should be based on the server time and preferably in relative terms
        (time remaining); the 'Date' header is a straightforward and generalizable way for client-side code to get this
        reference.
        """
        response = super().finalize_response(request, response, *args, **kwargs)
        # Adding this header should be moved to global middleware, not just this endpoint
        return expose_header('Date', response)


class Accounts(APIView):
    authentication_classes = (
        JwtAuthentication,
        BearerAuthenticationAllowInactiveUser,
        SessionAuthenticationAllowInactiveUser,
    )    
    permission_classes = (IsStaffOrOwner,)

    def get(self, request):
        """
        GET /lms_custom/api/v1/accounts
        """
        return Response({'username': request.user.username, 'email': request.user.email})

    def post(self, request):
        """
        Creates a new user account
        URL: /lms_custom/api/v1/accounts
        Arguments:
            request (HttpRequest)
            JSON (application/json)
            {
                "username": "staff4",
                "email": "staff4@example.com",
                "name": "stafftest"
            }
        Returns:
            HttpResponse: 200 on success, {"user_id ": 9}
            HttpResponse: 400 if the request is not valid.
            HttpResponse: 409 if an account with the given username or email
                address already exists
        """
        data = request.data

        # Generate a secure random password of 32 characters
        alphabet = string.ascii_letters + string.digits  # a-z, A-Z, 0-9
        password = ''.join(secrets.choice(alphabet) for _ in range(32))

        # set the honor_code and honor_code like checked,
        # so we can use the already defined methods for creating an user
        data['honor_code'] = "True"
        data['terms_of_service'] = "True"
        data['password'] = password
        data['send_activation_email'] = False

        email = data.get('email')
        username = data.get('username')

        # Handle duplicate email/username
        if User.objects.filter(email=email).exists() or User.objects.filter(username=username).exists():
            errors = {"user_message": "User already exists"}
            return Response(errors, status=409)

        try:
            # Create user without transaction decorator
            with transaction.atomic():
                user = User.objects.create(
                    username=username,
                    email=email,
                    is_active=True
                )
                user.set_password(password)
                
                # Set name if provided
                if 'name' in data:
                    user.first_name = data['name'].split(' ')[0]
                    user.last_name = data['name'].split(' ')[1]
                
                user.save()
                
                # Create user profile
                from common.djangoapps.student.models import UserProfile
                profile = UserProfile(user=user)
                profile.name = data.get('name', '')
                profile.save()

            user_id = user.id
            return Response({'user_id': user_id}, status=200)

        except Exception as err:
            logger.error(f"Error creating user: {str(err)}", exc_info=True)
            errors = {"user_message": "Error creating user account"}
            return Response(errors, status=400)


class ChangeUserPassword(APIView):
    authentication_classes = (
        JwtAuthentication,
        BearerAuthenticationAllowInactiveUser,
        SessionAuthenticationAllowInactiveUser,
    )
    permission_classes = (IsStaffOrOwner,)

    def post(self, request):
        """
        Change user password
        URL: /lms_custom/api/v1/change_user_password
        Arguments:
            request (HttpRequest)
            JSON (application/json)
            {
                "username": "staff4",
                "email": "staff4@example.com",
                "password": "knysys@123"
            }
        Returns:
            HttpResponse: 200 on success, {"user_id ": 9}
            HttpResponse: 400 if the request is not valid.
            HttpResponse: 403 if the request user is not is_staff and is_superuser.
            HttpResponse: 404 if an account with the given username or email
                not exists
        """
        data = request.data
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')
        if not User.objects.filter(email=email, username=username).exists():
            errors = {"user_message": "User not exists"}
            return Response(errors, status=404)

        if not (request.user.is_staff or request.user.is_superuser):
            print("User %s does not have sufficient permissions", request.user)
            return Response(
                {"message": "Insufficient permissions"},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            # Change user password
            user = User.objects.get(email=email, username=username)
            user.set_password(password)
            user.save()
            user_id = user.id
            return Response({'user_id': user_id}, status=200)

        except Exception as err:
            logger.error(f"Error changing password: {str(err)}", exc_info=True)
            errors = {"user_message": "Error changing password"}
            return Response(errors, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class ModifyAccessAPIView(APIView):
    authentication_classes = (
        JwtAuthentication,
        BearerAuthenticationAllowInactiveUser,
    )
    permission_classes = (IsAuthenticated,)

    def post(self, request, course_id):
        """
        Modify staff/instructor access of other user.
        Requires instructor access.
        """
        if not (request.user.is_staff or request.user.is_superuser):
            print("User %s does not have sufficient permissions", request.user)
            return Response(
                {"message": "Insufficient permissions"},
                status=status.HTTP_403_FORBIDDEN
            )
        course_id = CourseKey.from_string(course_id)
        course = get_course_with_access(
            request.user, 'instructor', course_id, depth=None
        )

        unique_student_identifier = request.data.get('unique_student_identifier')
        rolename = request.data.get('rolename')
        action = request.data.get('action')
        is_course_creator = request.data.get('is_course_creator')

        try:
            user = get_student_from_identifier(unique_student_identifier)
            if user and is_course_creator:
                user.is_staff = True
                user.save()
        except User.DoesNotExist:
            return Response(
                {
                    'unique_student_identifier': unique_student_identifier,
                    'userDoesNotExist': True,
                },
                status=status.HTTP_404_NOT_FOUND
            )

        if not user.is_active:
            return Response(
                {
                    'unique_student_identifier': user.username,
                    'inactiveUser': True,
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        if rolename not in ROLES:
            error = strip_tags(f"unknown rolename '{rolename}'")
            return Response({'error': error}, status=status.HTTP_400_BAD_REQUEST)

        if rolename == 'instructor' and user == request.user and action != 'allow':
            return Response(
                {
                    'unique_student_identifier': user.username,
                    'rolename': rolename,
                    'action': action,
                    'removingSelfAsInstructor': True,
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        if action == 'allow':
            allow_access(course, user, rolename)
            if not is_user_enrolled_in_course(user, course_id):
                CourseEnrollment.enroll(user, course_id)
        elif action == 'revoke':
            revoke_access(course, user, rolename)
        else:
            return Response(
                {'error': strip_tags(f"unrecognized action '{action}'")},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response(
            {
                'unique_student_identifier': user.username,
                'rolename': rolename,
                'action': action,
                'success': 'yes',
            },
            status=status.HTTP_200_OK
        )


class DeleteEdxUser(APIView):
    authentication_classes = (
        JwtAuthentication,
        BearerAuthenticationAllowInactiveUser,
        SessionAuthenticationAllowInactiveUser,
    )
    permission_classes = (IsStaffOrOwner,)

    def delete(self, request):
        """
        Change user password
        URL: /lms_custom/api/v1/delete_edx_user
        Arguments:
            request (HttpRequest)
            JSON (application/json)
            {
                "username": "staff4",
                "email": "staff4@example.com",
            }
        Returns:
            HttpResponse: 200 on success, {"user_id ": 9}
            HttpResponse: 400 if the request is not valid.
            HttpResponse: 403 if the request user is not is_staff and is_superuser.
            HttpResponse: 404 if an account with the given username or email
                not exists
        """
        data = request.data
        email = data.get('email')
        username = data.get('username')

        if not User.objects.filter(email=email, username=username).exists():
            errors = {"user_message": "User not exists"}
            return Response(errors, status=404)

        if not (request.user.is_staff or request.user.is_superuser):
            print("User %s does not have sufficient permissions", request.user)
            return Response(
                {"message": "Insufficient permissions"},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            user = User.objects.get(email=email, username=username)

            # Delete enrollments
            CourseEnrollment.objects.filter(user=user).delete()

            # Delete roles
            CourseAccessRole.objects.filter(user=user).delete()

            # Delete course progress data
            StudentModule.objects.filter(student=user).delete()

            # Delete social auth
            UserSocialAuth.objects.filter(user=user).delete()

            # Delete profile
            UserProfile.objects.filter(user=user).delete()

            # Delete course creator
            token = request.headers.get("Authorization")
            cms_url = "https://studio.portal.nce.center/api/contentstore/v2/delete/course_creator"

            try:
                cms_response = requests.delete(
                    cms_url,
                    json={"email": email, "username": username},
                    headers={"Authorization": token} if token else {},
                    timeout=5
                )
            except requests.exceptions.Timeout:
                cms_response = None
                logger.warning("CMS API call timed out after 5 seconds")

            # Finally delete user
            user_id = user.id
            user.delete()

            return Response({"message": "User and related data deleted", "user_id": user_id}, status=200)
        except Exception as err:
            logger.error(f"Error changing password: {str(err)}", exc_info=True)
            errors = {"user_message": "Error changing password"}
            return Response(errors, status=400)


class DeleteUserEnrollment(APIView):
    authentication_classes = (
        JwtAuthentication,
        BearerAuthenticationAllowInactiveUser,
        SessionAuthenticationAllowInactiveUser,
    )
    permission_classes = (IsStaffOrOwner,)

    def delete(self, request):
        """
        Delete a user's enrollment from a specific course.
        
        URL: /lms_custom/api/v1/delete_user_enrollment
        
        Arguments:
            request (HttpRequest)
            JSON (application/json):
            {
                "username": "staff4",
                "email": "staff4@example.com",
                "course_id": "course-v1:test+CS100+2025"
            }
            
        Returns:
            HttpResponse: 200 on success with user_id and course_id
            HttpResponse: 400 if the request is not valid
            HttpResponse: 403 if the request user doesn't have permission
            HttpResponse: 404 if user or enrollment is not found
        """
        data = request.data
        email = data.get('email')
        username = data.get('username')
        course_id = data.get('course_id')

        # Input validation
        if not all([email, username, course_id]):
            return Response(
                {"message": "Missing required fields: email, username, or course_id"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Permission check
        if not (request.user.is_staff or request.user.is_superuser):
            logger.warning(
                "User %s attempted to delete enrollment without permission",
                request.user.username
            )
            return Response(
                {"message": "Insufficient permissions"},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            # Get the user object
            try:
                user = User.objects.get(email=email, username=username)
            except User.DoesNotExist:
                logger.warning("User not found with email=%s, username=%s", email, username)
                return Response(
                    {"message": "User not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Get and delete the specific enrollment
            try:
                enrollment = CourseEnrollment.objects.get(
                    user=user,
                    course_id=course_id
                )
                
                # Log before deletion
                logger.info(
                    "Deleting enrollment - User: %s (%s), Course: %s",
                    user.username,
                    user.email,
                    course_id
                )
                
                # Perform the deletion
                enrollment.delete()
                
                logger.info(
                    "Successfully deleted enrollment - User: %s, Course: %s",
                    user.username,
                    course_id
                )
                
                return Response({
                    "message": "User enrollment deleted successfully",
                    "user_id": user.id,
                    "course_id": course_id
                }, status=status.HTTP_200_OK)
                
            except CourseEnrollment.DoesNotExist:
                logger.warning(
                    "Enrollment not found for user %s in course %s",
                    user.username,
                    course_id
                )
                return Response(
                    {"message": "User is not enrolled in this course"},
                    status=status.HTTP_404_NOT_FOUND
                )
                
        except Exception as err:
            logger.error(
                "Error deleting enrollment for user %s in course %s: %s",
                username,
                course_id,
                str(err),
                exc_info=True
            )
            return Response(
                {"message": "An error occurred while processing your request"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class CourseCreatorAPIView(APIView):
    authentication_classes = (
        JwtAuthentication,
        BearerAuthenticationAllowInactiveUser,
    )
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        """
        Modify staff/instructor access of other user.
        Requires instructor access.
        """
        if not (request.user.is_staff or request.user.is_superuser):
            print("User %s does not have sufficient permissions", request.user)
            return Response(
                {"message": "Insufficient permissions"},
                status=status.HTTP_403_FORBIDDEN
            )

        username = request.data.get('username')
        email = request.data.get('email')
        is_course_creator = request.data.get('is_course_creator')

        if username is None or email is None or is_course_creator is None:
            return Response(
                {"message": "username, email, and is_course_creator are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user =  User.objects.get(email=email, username=username)
            user.is_staff = bool(is_course_creator)
            user.save()
            action = "added" if user.is_staff else "removed"
        except User.DoesNotExist:
            return Response(
                {
                    'username': username,
                    'email': email,
                    'userDoesNotExist': True,
                },
                status=status.HTTP_404_NOT_FOUND
            )

        return Response(
                {"success": f"User course creator role {action} successfully"},
                status=status.HTTP_200_OK
            )


class LogoutAPIView(APIView):
    """
    API version of LogoutView
    Logs out user and returns JSON with redirect info and logout URIs.
    """
    oauth_client_ids = []
    default_target = '/'
    tpa_logout_url = ''

    def post(self, request, *args, **kwargs):
        return self.get(request, *args, **kwargs)

    @property
    def target(self):
        target_url = self.request.GET.get('redirect_url') or self.request.GET.get('next')

        if target_url:
            target_url = bleach.clean(parse.unquote(parse.quote_plus(target_url)))

        use_target_url = target_url and is_safe_login_or_logout_redirect(
            redirect_to=target_url,
            request_host=self.request.get_host(),
            dot_client_id=self.request.GET.get('client_id'),
            require_https=self.request.is_secure(),
        )
        return target_url if use_target_url else self.default_target

    def _build_logout_url(self, url):
        scheme, netloc, path, query_string, fragment = urlsplit(url)
        query_params = parse_qs(query_string)
        query_params['no_redirect'] = 1
        new_query_string = urlencode(query_params, doseq=True)
        return urlunsplit((scheme, netloc, path, new_query_string, fragment))

    def _is_enterprise_target(self, url):
        unquoted_url = parse.unquote_plus(parse.quote(url))
        return bool(re.match(r'^/enterprise(/handle_consent_enrollment)?/[a-z0-9\-]+/course', unquoted_url))

    def _show_tpa_logout_link(self, target, referrer):
        tpa_automatic_logout_enabled = getattr(settings, 'TPA_AUTOMATIC_LOGOUT_ENABLED', False)
        if (
            bool(target == self.default_target and self.tpa_logout_url) and
            settings.LEARNER_PORTAL_URL_ROOT in referrer and
            not tpa_automatic_logout_enabled
        ):
            return True
        return False

    def get(self, request, *args, **kwargs):
        # Set up TPA logout URL
        self.tpa_logout_url = tpa_pipeline.get_idp_logout_url_from_running_pipeline(request)

        # Perform Django logout
        logout(request)

        response = Response(status=status.HTTP_200_OK)

        # Clear cookies
        delete_logged_in_cookies(response)
        mark_user_change_as_expected(None)

        # If automatic TPA logout is enabled, redirect immediately
        if getattr(settings, 'TPA_AUTOMATIC_LOGOUT_ENABLED', False):
            if self.tpa_logout_url:
                return Response({
                    "redirect": self.tpa_logout_url,
                    "automatic_tpa_logout": True
                }, status=status.HTTP_200_OK)

        # Build logout URIs
        uris = []
        uris += Application.objects.filter(
            client_id__in=self.oauth_client_ids,
            redirect_uris__isnull=False
        ).values_list('redirect_uris', flat=True)

        uris += settings.IDA_LOGOUT_URI_LIST

        referrer = request.META.get('HTTP_REFERER', '').strip('/')
        logout_uris = []

        for uri in uris:
            if not referrer or (referrer and not uri.startswith(referrer)):
                logout_uris.append(self._build_logout_url(uri))

        target = self.target
        data = {
            'target': target,
            'logout_uris': logout_uris,
            'enterprise_target': self._is_enterprise_target(target),
            'tpa_logout_url': self.tpa_logout_url,
            'show_tpa_logout_link': self._show_tpa_logout_link(target, referrer),
        }

        response.data = data
        return response


class ProgressCourseView(APIView):
    authentication_classes = (
        JwtAuthentication,
        BearerAuthenticationAllowInactiveUser,
    )
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        student = User.objects.get(email=request.user.email)
        enrollments = CourseEnrollment.objects.filter(user=student, is_active=True)

        progress_data = []

        for enrollment in enrollments:
            course_key = enrollment.course_id
            try:
                is_staff = bool(has_access(request.user, 'staff', course_key))

                collected_block_structure = get_block_structure_manager(course_key).get_collected()
                course_grade = CourseGradeFactory().read(student, collected_block_structure=collected_block_structure)

                # Recalculate grades for visible content only
                course_grade.update(visible_grades_only=True, has_staff_access=is_staff)

                grade_data = course_grade.summary
                grade_data["course_id"] = str(course_key)

                progress_data.append(grade_data)

            except (ItemNotFoundError, BlockStructureNotFound):
                # Skip courses that are missing or have no block structure
                continue

        return JsonResponse({'response': progress_data})
