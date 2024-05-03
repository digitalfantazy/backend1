from django.db.models.signals import post_save
from django.conf import settings
from django.dispatch import receiver
from django.core.mail import EmailMessage
from django.utils import timezone
from django.dispatch import Signal

from backend.settings import FRONT_URL, EMAIL_HOST_USER

from .models import OtpToken



user_registered = Signal()
 
@receiver(post_save, sender=settings.AUTH_USER_MODEL) 
def create_token(sender, instance, created, **kwargs):
    if created:
        if instance.is_superuser:
            pass
        
        else:
            OtpToken.objects.create(user=instance, otp_expires_at=timezone.now() + timezone.timedelta(minutes=5))
            instance.email_verified=False 
            instance.save()
        
        
        # email credentials
        otp = OtpToken.objects.filter(user=instance).last()
      
        subject = "Подтверждение электронного адреса"
        message = f"""
            <html>
            <head>
                <style>
                    body {{
                        font-family: 'Arial', sans-serif;
                        font-size: 14px;
                        color: #333;
                    }}
                    p {{
                        margin: 10px 0;
                    }}
                    strong {{
                        font-size: 16px;
                        color: #000;
                    }}
                    a {{
                        color: #0645AD;
                        text-decoration: none;
                    }}
                    .greeting {{
                        font-size: 16px;
                    }}
                </style>
            </head>
            <body>
                <p class="greeting">Здравствуйте, <strong>{instance.name}</strong>!</p>
                <p>Ваш код подтверждения: <strong>{otp.otp_code}</strong></p>
                <p>Данный код действителен в течение 5 минут. Если код истек, вы можете запросить новый.</p>
                <p>Используйте этот код для подтверждения вашего электронного адреса на сайте.</p>
                <p>Вы также можете активировать свой аккаунт, перейдя по <a href="{FRONT_URL}/auth/verify-email/{instance.username}">ссылке</a>.</p>
                <br>
                <p>Спасибо за регистрацию!</p>
            </body>
            </html>
            """
        email = EmailMessage(
            subject,
            message,
            EMAIL_HOST_USER,
            [instance.email],
            headers={'Content-Type': 'text/html'}
        )
        email.content_subtype = "html"  # Если используете EmailMessage, установите этот параметр
        email.send(fail_silently=False)
  