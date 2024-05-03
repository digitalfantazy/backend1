from django.db import models
from django.core.validators import MinLengthValidator, MaxLengthValidator
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
from django.conf import settings
import secrets


class UserAccountManager(BaseUserManager):
    def create_user(self, name, username, email, password=None):
        
        if not email:
            raise ValueError("Users must have an email address")

        email = self.normalize_email(email)
        email = email.lower()

        user = self.model(
            name=name,
            username=username,
            email=email,

        )

        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, name, username, email, password=None):

        user = self.create_user(
            name=name,
            username=username,
            email=email,
            password=password,
        )
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class UserAccount(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(unique=True, max_length=255, validators=[MinLengthValidator(3, message='Имя пользователя должно содержать не менее 3 символов'), MaxLengthValidator(20, message='Имя пользователя не должно превышать 20 символов')])
    email = models.EmailField(unique=True, max_length=255)
    name = models.CharField(max_length=255, default='')
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    email_verified = models.BooleanField(default=False)

    
    objects = UserAccountManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email", "name"]

    def __str__(self):
        return self.username
      
class OtpToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="otps")
    otp_code = models.CharField(max_length=6, default=secrets.token_hex(3))
    tp_created_at = models.DateTimeField(auto_now_add=True)
    otp_expires_at = models.DateTimeField(blank=True, null=True)
    
    # def __str__(self):
    #     return self.user.username

class RefreshSession(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    fingerprint = models.CharField(max_length=200)
    refresh_token = models.CharField(max_length=400, unique=True) 
    expires_in = models.BigIntegerField()  # Время жизни токена в секундах
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"RefreshSession for user {self.user.username}"