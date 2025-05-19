from django.db import models
from django.contrib.auth.models import User
# Create your models here.
User.add_to_class('tocken_mail', models.TextField(null=True))