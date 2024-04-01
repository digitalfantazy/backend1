from django.urls import path
from .views import RegisterView, RetrieveUserView, LogoutView, get_pdf

urlpatterns = [
    path('users/register', RegisterView.as_view()),
    path('users/me', RetrieveUserView.as_view()),
    path('users/logout', LogoutView.as_view()),
    path('pdf/<str:lab_id>/<str:param>', get_pdf, name='get_pdf')
]

