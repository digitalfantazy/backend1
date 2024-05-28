from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status, generics
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.exceptions import InvalidToken
import requests
import os

from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.mail import EmailMessage
from django.core.exceptions import ValidationError

from backend.settings import FRONT_URL, EMAIL_HOST_USER, SELECTEL_API_AUTH_TOKEN

from base.models import OtpToken, RefreshSession, UserAccount, BooksCard, PDFFile
from base.signals import user_registered

from .serializers import UserCreateSerializer, UserSerializer, ChangePasswordSerializer, CardSerializer
from .utils import get_selectel_token

# @method_decorator(ensure_csrf_cookie, name='dispatch')
class RegisterView(APIView):

    # @method_decorator(csrf_protect)
    def post(self, request):
        data = request.data
        # print(data['username'])
        serializer = UserCreateSerializer(data=data)
        # print(serializer)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.save()
        user.is_active = False  # Делаем пользователя неактивным пока не подтвердит email
        user.save()
        # user.is_active = False
        # user = serializer.create(serializer.validated_data)
        user_registered.send(sender=self.__class__, instance=user, created=True)

        user = UserSerializer(user)

        # print("2",user)

        return Response(user.data, status=status.HTTP_201_CREATED)

class VerifyEmail(APIView):

    def post(self, request, username):
        try:
            user = get_user_model().objects.get(username=username)
            user_otp = OtpToken.objects.filter(user=user).order_by('-tp_created_at').first()

            if not user_otp:
                return Response("No OTP token found", status=status.HTTP_404_NOT_FOUND)

            if request.method == 'POST':
                otp_code = request.data.get('opt_code')
                if not otp_code:
                    return Response("Invalid request: 'otp_code' parameter is missing.",status=status.HTTP_400_BAD_REQUEST)
            
            if user_otp and user_otp.otp_code == otp_code:
                if user_otp.otp_expires_at > timezone.now():
                    user.is_active = True
                    user.email_verified = True
                    user.save()

                    user_otp.delete() 
                    return Response("Account activated successfully", status=status.HTTP_200_OK)
                
                else:
                    return Response("OTP expired", status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response("Invalid OTP", status=status.HTTP_400_BAD_REQUEST)
        except get_user_model().DoesNotExist:
           return Response("User not found", status=status.HTTP_400_BAD_REQUEST)

class ResenedVerificationCode(APIView):

    def post(self, request):
        if request.method == 'POST':
            user_email = request.data.get("email")

            try:
                user = get_user_model().objects.get(email=user_email)
            except get_user_model().DoesNotExist:
                return Response("This email doesn't exist in the database", status=status.HTTP_404_NOT_FOUND)

            otp = OtpToken.objects.create(user=user, otp_expires_at=timezone.now() + timezone.timedelta(minutes=5)) 
                # email variables
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
                    <p class="greeting">Здравствуйте, <strong>{user.name}</strong>!</p>
                    <p>Ваш код подтверждения: <strong>{otp.otp_code}</strong></p>
                    <p>Данный код действителен в течение 5 минут. Если код истек, вы можете запросить новый.</p>
                    <p>Используйте этот код для подтверждения вашего электронного адреса на сайте.</p>
                    <p>Вы также можете активировать свой аккаунт, перейдя по <a href="{FRONT_URL}/auth/verify-email/{user.username}">ссылке</a>.</p>
                    <br>
                    <p>Спасибо за регистрацию!</p>
                </body>
                </html>
                """
            email = EmailMessage(
                subject,
                message,
                EMAIL_HOST_USER,
                [user.email],
                headers={'Content-Type': 'text/html'}
            )
            email.content_subtype = "html"  # Если используете EmailMessage, установите этот параметр
            email.send(fail_silently=False)
  
                
        return Response("A new OTP has been sent to your email-address", status=status.HTTP_200_OK)

class RetrieveUserView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        user = UserSerializer(user)

        return Response(user.data, status=status.HTTP_200_OK)

class CookieTokenRefreshSerializer(TokenRefreshSerializer):
    refresh = None
    def validate(self, attrs):
        attrs['refresh'] = self.context['request'].COOKIES.get('refresh_token')
        if attrs['refresh']:
            return super().validate(attrs)
        else:
            raise InvalidToken('No valid token found in cookie \'refresh_token\'')
        
# @method_decorator(ensure_csrf_cookie, name='dispatch')
class CookieTokenObtainPairView(TokenObtainPairView):
    
    # @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            refresh_token = response.data.get('refresh')
            fingerprint = request.META.get('HTTP_USER_AGENT', '')

            username = request.data.get('username')

            try:
                user = UserAccount.objects.get(username=username)
            except UserAccount.DoesNotExist:
                raise Exception("User does not exist")
            
            try:
                refresh_session = RefreshSession.objects.get(user=user)
                refresh_session.refresh_token = refresh_token
                refresh_session.fingerprint = fingerprint
                refresh_session.expires_in = RefreshToken(refresh_token).payload['exp']
                refresh_session.save()
            except RefreshSession.DoesNotExist:
                expires_in = RefreshToken(refresh_token).payload['exp']
                refresh_session = RefreshSession.objects.create(
                    user=user,
                    refresh_token=refresh_token,
                    fingerprint=fingerprint,
                    expires_in=expires_in
                )

            cookie_max_age = 3600 * 24  # 1 day
            response.set_cookie('refresh_token', refresh_token, max_age=cookie_max_age, samesite='None', httponly=True, secure=True)
            del response.data['refresh']
        
        return response
    
# @method_decorator(ensure_csrf_cookie, name='dispatch')
class CookieTokenRefreshView(TokenRefreshView):

    # @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        fingerprint = request.META.get('HTTP_USER_AGENT', '')
        refresh_token = request.COOKIES.get('refresh_token')
        
        if not refresh_token:
            return HttpResponse("No refresh token provided", status=status.HTTP_400_BAD_REQUEST)

        try:
            refresh_session = RefreshSession.objects.get(refresh_token=refresh_token)
            if (refresh_session.expires_in > timezone.now().timestamp()) and (refresh_session.fingerprint == fingerprint):
                response = super().post(request, *args, **kwargs)
                if response.status_code == 200:
                    refresh_token_new = response.data.get('refresh')
                    refresh_session.refresh_token = refresh_token_new
                    refresh_session.expires_in = RefreshToken(refresh_token_new).payload['exp']
                    refresh_session.save()

                    cookie_max_age = 3600 * 24  # 1 day
                    response.set_cookie('refresh_token', refresh_token_new, max_age=cookie_max_age, samesite='None', httponly=True, secure=True)
                    del response.data['refresh']

                return response
            else:
                return HttpResponse("Refresh session expired OR Refresh session not found OR Fingerprint mismatch", status=status.HTTP_404_NOT_FOUND)
        except RefreshSession.DoesNotExist:
            return HttpResponse("Refresh session not found", status=status.HTTP_404_NOT_FOUND)

    serializer_class = CookieTokenRefreshSerializer

class LogoutView(APIView):

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        # print(refresh_token)

        try:
            refresh_session = RefreshSession.objects.get(refresh_token=refresh_token)
            # print(refresh_session)
            refresh_session.delete()

        except RefreshSession.DoesNotExist:
            return Response("Refresh session not found", status=status.HTTP_404_NOT_FOUND)
        
        # Удаляем refreshToken из кук
        response = Response({"message": "Successfully logged out."})
        response.delete_cookie('refresh_token')
        # response.delete_cookie('sessionid')
        # response.delete_cookie('csrftoken')
        # Вызываем функцию logout() для выхода пользователя из системы
        # logout(request) Нужно вернуть респоснс, с логаут (возможно нет куки)
        return response
        
class GetPdfView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    # @csrf_exempt
    def get(self, request, lab_id, param):
        pdf_path = os.path.join(settings.MEDIA_ROOT, f'{lab_id}_{param}.pdf')
        print(f"Requested PDF path: {pdf_path}")

        if os.path.exists(pdf_path):
            with open(pdf_path, 'rb') as pdf_file:
                response = HttpResponse(pdf_file.read(), content_type='application/pdf')
                response['Content-Disposition'] = f'inline; filename="{lab_id}_{param}.pdf"'
                return response
        else:
            print("PDF file not found")
            return HttpResponse('PDF file not found', status=404)
            
class ChangePassword(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        print(request.data)
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            request.user.set_password(serializer.validated_data['new_password'])
            request.user.save()
            return Response({"detail": "Password updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CardListView(generics.ListAPIView):
    queryset = BooksCard.objects.all()
    serializer_class = CardSerializer
    


class GetPdfFromSelectelView(APIView):

    permission_classes = [permissions.IsAuthenticated]

# url = f'https://swift.ru-1.storage.selcloud.ru/v1/b7e2aca2ba59439d96d8b93c7111d121/pdf/osnovi_zashiti_inf.pdf'
    def get(self, request, filename):
        token = get_selectel_token()
        try:
            pdf_file = PDFFile.objects.get(name=filename)
        except PDFFile.DoesNotExist:
            return HttpResponse('PDF file not found', status=404)

        headers = {'X-Auth-Token': token}
        print(pdf_file.url)
        response = requests.get(pdf_file.url, headers=headers)
        
        if response.status_code == 200:
            return HttpResponse(response.content, content_type='application/pdf')
        else:
            return HttpResponse('PDF file not found', status=404)


