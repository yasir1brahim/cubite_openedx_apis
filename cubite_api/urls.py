from django.urls import path
from . import views

app_name = 'cubite_api'

urlpatterns = [
    path('enrollment', views.Enrollments.as_view(), name='enrollment'),
    path('get_user_info', views.GetUserInfo.as_view(), name='get_user_info'),
    path('get_course_outline', views.GetCourseOutline.as_view(), name='get_course_outline'),
    path('accounts', views.Accounts.as_view(), name='accounts'),
    path('change_user_password', views.ChangeUserPassword.as_view(), name='change_user_password'),
    path('modify-instructor-access/<str:course_id>/', views.ModifyAccessAPIView.as_view(), name='modify_instructor_access'),
    path('delete-user-enrollment', views.DeleteUserEnrollment.as_view(), name='delete_user_enrollment'),
    path('delete-edx-user', views.DeleteEdxUser.as_view(), name='delete_edx_user'),
    path('modify-creator-access', views.CourseCreatorAPIView.as_view(), name='modify_creator_access'),
    path('logout_api', views.LogoutAPIView.as_view(), name='logout_api'),
    path('progress', views.ProgressCourseView.as_view(), name='progress'),
    path('get_public_course_outline', views.GetPublicCourseOutline.as_view(), name='get_public_course_outline'),
]
