from django.db import models

# Create your models here.
class Users(models.Model):
    name = models.CharField(max_length=64)
    publicKey = models.CharField(max_length=1024)
    privateKey = models.CharField(max_length=1024)
    symKey = models.CharField(max_length=1024)

