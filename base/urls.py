from django.urls import path
from .views import RegisterView, RetrieveUserView, LogoutView

urlpatterns = [
    path('register', RegisterView.as_view()),
    path('me', RetrieveUserView.as_view()),
    path('logout', LogoutView.as_view())
]
