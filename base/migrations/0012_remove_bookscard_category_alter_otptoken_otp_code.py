# Generated by Django 5.0.2 on 2024-05-27 00:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0011_alter_otptoken_otp_code'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='bookscard',
            name='category',
        ),
        migrations.AlterField(
            model_name='otptoken',
            name='otp_code',
            field=models.CharField(default='a186df', max_length=6),
        ),
    ]
