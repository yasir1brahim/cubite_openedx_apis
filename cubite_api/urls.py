from django.urls import path
from . import views

app_name = 'cubite_api'

urlpatterns = [
    path('enrollment', views.Enrollments.as_view(), name='enrollment'),
    path('get_user_info', views.GetUserInfo.as_view(), name='get_user_info'),
    path('get_course_outline', views.GetCourseOutline.as_view(), name='get_course_outline'),
]
