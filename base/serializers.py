from django.contrib.auth.password_validation import validate_password
from django.core import exceptions
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import re

User = get_user_model()


class UserCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('name', 'username', 'email', 'password')

    def validate_username_onlyENG(self, value):
        if not re.match(r'^[a-zA-Z0-9]+$', value):
            raise serializers.ValidationError({
                'username': ['user only english letters']
        })
        return value


    def validate(self, data):
        errors = {}
        user = User(**data)

        name = data.get('name')  # Получение имени из данных
        if not name:
            errors['name'] = ['Поле "Имя" обязательно для заполнения']  # Проверка наличия имени

        username = data.get('username')
        if username:
            username = self.validate_username_onlyENG(username)
            if len(username) < 3:
                errors['username'] = ['Имя пользователя должно содержать латинский буквы, не менее 3 символов']
            elif len(username) > 15:
                errors['username'] = ['The username must contain no more than 15 characters']

        email = data.get('email')
        if email: 
            try:
                validate_email(email)
            except exceptions.ValidationError:
                errors['email'] = ['Укажите верный адрес электронной почты']

        if errors:
            raise serializers.ValidationError(errors)

        password = data.get('password')
        if password:
            if not re.match(r'^[a-zA-Z0-9]+$', password):
                raise serializers.ValidationError({
                    'password': ['pass only english']
                })
            else:
                try:
                    validate_password(password, user)
                except exceptions.ValidationError as e:
                    serializer_errors = serializers.as_serializer_error(e)
                    raise exceptions.ValidationError(
                        {'password': serializer_errors['non_field_errors']}
                    )
        
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError({'username': 'Такое имя пользователя уже занято'})
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError({'email': 'Пользователь с таким email уже существует'})
        return data
    
    

    def create(self, validated_data):
        user = User.objects.create_user(
            name=validated_data['name'],
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
        )

        return user
    

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('name', 'username', 'email')