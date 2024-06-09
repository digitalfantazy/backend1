from django.urls import path
from .views import CookieTokenObtainPairView, CookieTokenRefreshView, LogoutView, RegisterView, ResenedVerificationCode, RetrieveUserView, GetPdfView, VerifyEmail, ChangePassword, GetPdfFromSelectelView, CardListView
from rest_framework_simplejwt.views import TokenVerifyView

urlpatterns = [
    path('auth/token/', CookieTokenObtainPairView.as_view()),
    path('auth/token/refresh/', CookieTokenRefreshView.as_view()),
    path('auth/token/verify/', TokenVerifyView.as_view()),

    path('auth/register', RegisterView.as_view()),
    path('auth/verify-email/<slug:username>', VerifyEmail.as_view(), name="verify-email"),
    path('auth/verify-email/user/resendcode', ResenedVerificationCode.as_view()),

    path("users/change-password", ChangePassword.as_view()),
    path('auth/logout', LogoutView.as_view(), name="logout"),

    path('users/me', RetrieveUserView.as_view()),
    path('pdf/<str:filename>/', GetPdfView.as_view(), name='get_pdf'),

    path('cards/', CardListView.as_view(), name='card_list'),
    path('get-pdf/<str:filename>/', GetPdfFromSelectelView.as_view(), name='get_pdf_from_selectel'),
]

