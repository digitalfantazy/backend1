# Generated by Django 5.0.2 on 2024-05-27 00:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0009_pdffile_alter_otptoken_otp_code_bookscard'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otptoken',
            name='otp_code',
            field=models.CharField(default='0b57e0', max_length=6),
        ),
    ]
