from django.db import models
from django.contrib.auth.models import User
# Create your models here.
User.add_to_class('secret_mfa_temp', models.TextField(null=True))
User.add_to_class('secret_mfa', models.TextField(null=True))

