# Generated by Django 5.1.7 on 2025-05-13 06:10

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Administrador', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name='entidad',
            name='userid',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='entidad', to=settings.AUTH_USER_MODEL),
        ),
    ]
