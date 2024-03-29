from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
from base.views import CookieTokenRefreshView, CookieTokenObtainPairView 



urlpatterns = [
   path('admin/', admin.site.urls),
   path('api/users/', include('base.urls')),

   path('api/token/', CookieTokenObtainPairView.as_view()),
   path('api/token/refresh/', CookieTokenRefreshView.as_view()),
   path('api/token/verify/', TokenVerifyView.as_view()),
]
