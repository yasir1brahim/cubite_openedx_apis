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
from django.contrib.auth.models import User

import logging


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
from common.djangoapps.student.models import CourseEnrollment
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
        

class GetCourseOutline(RetrieveAPIView):
    """
    **Use Cases**

        Request details for the Outline Tab

    **Example Requests**

        GET api/cubite/v1/get_course_outline?course_id=course-v1:edX+DemoX+Demo_Course&email=student@example.com

    **Response Values**

        Body consists of two possible shapes.

        For a good 200 response, the response will include:

        access_expiration: An object detailing when access to this course will expire
            expiration_date: (str) When the access expires, in ISO 8601 notation
            masquerading_expired_course: (bool) Whether this course is expired for the masqueraded user
            upgrade_deadline: (str) Last chance to upgrade, in ISO 8601 notation (or None if can't upgrade anymore)
            upgrade_url: (str) Upgrade link (or None if can't upgrade anymore)
        course_blocks:
            blocks: List of serialized Course Block objects. Each serialization has the following fields:
                id: (str) The usage ID of the block.
                type: (str) The type of block. Possible values the names of any
                    XBlock type in the system, including custom blocks. Examples are
                    course, chapter, sequential, vertical, html, problem, video, and
                    discussion.
                display_name: (str) The display name of the block.
                lms_web_url: (str) The URL to the navigational container of the
                    xBlock on the web LMS.
                children: (list) If the block has child blocks, a list of IDs of
                    the child blocks.
                resume_block: (bool) Whether the block is the resume block
                has_scheduled_content: (bool) Whether the block has more content scheduled for the future
        course_goals:
            selected_goal:
                days_per_week: (int) The number of days the learner wants to learn per week
                subscribed_to_reminders: (bool) Whether the learner wants email reminders about their goal
            weekly_learning_goal_enabled: Flag indicating if this feature is enabled for this call
        course_tools: List of serialized Course Tool objects. Each serialization has the following fields:
            analytics_id: (str) The unique id given to the tool.
            title: (str) The display title of the tool.
            url: (str) The link to access the tool.
        dates_banner_info: (obj)
            content_type_gating_enabled: (bool) Whether content type gating is enabled for this enrollment.
            missed_deadlines: (bool) Whether the user has missed any graded content deadlines for the given course.
            missed_gated_content: (bool) Whether the user has missed any gated content for the given course.
            verified_upgrade_link: (str) The URL to ecommerce IDA for purchasing the verified upgrade.
        dates_widget:
            course_date_blocks: List of serialized Course Dates objects. Each serialization has the following fields:
                complete: (bool) Meant to only be used by assignments. Indicates completeness for an
                assignment.
                date: (datetime) The date time corresponding for the event
                date_type: (str) The type of date (ex. course-start-date, assignment-due-date, etc.)
                description: (str) The description for the date event
                learner_has_access: (bool) Indicates if the learner has access to the date event
                link: (str) An absolute link to content related to the date event
                    (ex. verified link or link to assignment)
                title: (str) The title of the date event
            dates_tab_link: (str) The URL to the Dates Tab
            user_timezone: (str) The timezone of the given user
        enroll_alert:
            can_enroll: (bool) Whether the user can enroll in the given course
            extra_text: (str)
        enrollment_mode: (str) Current enrollment mode. Null if the user is not enrolled.
        handouts_html: (str) Raw HTML for the handouts section of the course info
        has_ended: (bool) Indicates whether course has ended
        offer: An object detailing upgrade discount information
            code: (str) Checkout code
            expiration_date: (str) Expiration of offer, in ISO 8601 notation
            original_price: (str) Full upgrade price without checkout code; includes currency symbol
            discounted_price: (str) Upgrade price with checkout code; includes currency symbol
            percentage: (int) Amount of discount
            upgrade_url: (str) Checkout URL
        resume_course:
            has_visited_course: (bool) Whether the user has ever visited the course
            url: (str) The display name of the course block to resume
        welcome_message_html: (str) Raw HTML for the course updates banner
        user_has_passing_grade: (bool) Whether the user currently is passing the course

        If the learner does not have access to the course for a specific reason and should be redirected this
        view will return a 403 and the following data:

        url: (str) The URL to which the user should be redirected
        error_code: (str) A system identifier for the reason the user is being redirected
        developer_message: (str) A message explaining why the user is being redirected,
                                 intended for developer debugging.
        user_message: (str) A message explaining why the user is being redirected, intended to be shown to the user.

    **Returns**

        * 200 on success.
        * 403 if the user does not currently have access to the course and should be redirected.
        * 404 if the course is not available or cannot be seen.

    """

    authentication_classes = (
        JwtAuthentication,
        BearerAuthenticationAllowInactiveUser,
        SessionAuthenticationAllowInactiveUser,
    )

    serializer_class = OutlineTabSerializer

    def get(self, request, *args, **kwargs):  # pylint: disable=too-many-statements
        course_key_string = request.query_params.get('course_id')
        email = request.query_params.get('email')
        course_key = CourseKey.from_string(course_key_string)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"message": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)
        
        # make sure requets.user is staff if not return 403
        if not request.user.is_staff:
            return Response({"message": "User does not have sufficient permissions"}, status=status.HTTP_403_FORBIDDEN)

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

        # Sometimes there are sequences returned by Course Blocks that we
        # don't actually want to show to the user, such as when a sequence is
        # composed entirely of units that the user can't access. The Learning
        # Sequences API knows how to roll this up, so we use it determine which
        # sequences we should remove from course_blocks.
        #
        # The long term goal is to remove the Course Blocks API call entirely,
        # so this is a tiny first step in that migration.
        if course_blocks:
            user_course_outline = get_user_course_outline(
                course_key, user, datetime.now(tz=timezone.utc)
            )
            available_seq_ids = {str(usage_key) for usage_key in user_course_outline.sequences}

            available_section_ids = {str(section.usage_key) for section in user_course_outline.sections}

            # course_blocks is a reference to the root of the course,
            # so we go through the chapters (sections) and keep only those
            # which are part of the outline.
            course_blocks['children'] = [
                chapter_data
                for chapter_data in course_blocks.get('children', [])
                if chapter_data['id'] in available_section_ids
            ]

            # course_blocks is a reference to the root of the course, so we go
            # through the chapters (sections) to look for sequences to remove.
            for chapter_data in course_blocks['children']:
                chapter_data['children'] = [
                    seq_data
                    for seq_data in chapter_data['children']
                    if (
                        seq_data['id'] in available_seq_ids or
                        # Edge case: Sometimes we have weird course structures.
                        # We expect only sequentials here, but if there is
                        # another type, just skip it (don't filter it out).
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
        context = self.get_serializer_context()
        context['course_overview'] = course_overview
        context['enable_links'] = show_enrolled or allow_public
        context['enrollment'] = enrollment
        serializer = self.get_serializer_class()(data, context=context)

        return Response(serializer.data)


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
