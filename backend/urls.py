from django.contrib import admin
from django.urls import path, include

# from base.views import LogoutView



urlpatterns = [
   path('admin/', admin.site.urls),
   path('api/', include('base.urls')),
]
