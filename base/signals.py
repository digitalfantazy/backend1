from django.db.models.signals import post_save
from django.conf import settings
from django.dispatch import receiver
from django.core.mail import send_mail
from django.utils import timezone
from django.dispatch import Signal

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
    
       
       
        subject="Email Verification"
        message = f"""
                                Здравствуйте,  {instance.name}!, ваш код: {otp.otp_code} 
                                Используйте его для того чтобы подтвержить ваш адрес электронной почты, 
                                use the url below to redirect back to the website
                                http://127.0.0.1:8000/api/verify-email/{instance.username}
                                
                                """
        sender = "artemaa5809@yandex.ru"
        receiver = [instance.email, ]
       
        
        
        # send email
        send_mail(
                subject,
                message,
                sender,
                receiver,
                fail_silently=False,
            )
  