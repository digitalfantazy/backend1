from django.db import models
from django.core.validators import MinLengthValidator, MaxLengthValidator
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin


class UserAccountManager(BaseUserManager):
    def create_user(self, username, email, password=None):
        if not email:
            raise ValueError("Users must have an email address")

        email = self.normalize_email(email)
        email = email.lower()

        user = self.model(
            username=username,
            email=email,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, username, email, password=None):

        user = self.create_user(
            username=username,
            email=email,
            password=password,
        )
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class UserAccount(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(unique=True, max_length=255, validators=[MinLengthValidator(3, message='Имя пользователя должно содержать не менее 3 символов'), MaxLengthValidator(5, message='Имя пользователя должно превышать 20 символов')])
    email = models.EmailField(unique=True, max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    
    objects = UserAccountManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = [""]

    def __str__(self):
        return self.username