from django.db import models
import base64
from django.contrib.auth.models import *

class Message(models.Model):
    sender = models.CharField(max_length=64)
    content = models.BinaryField()

    def __str__(self):
        return f"{self.content}"

class Group(models.Model):
    groupName = models.CharField(max_length=64)
    messages = models.ManyToManyField(Message, related_name="group", blank=True)
    currSymKey = models.BinaryField()

    def __str__(self):
        return f"{self.groupName}" 

# class GroupUser(models.Model):
#     user = models.OneToOneField(User, on_delete=models.CASCADE)
#     isAdmin = models.BooleanField(default=False)
#     group = models.ForeignKey(Group, on_delete=models.CASCADE, blank=True)
#     symKey = models.BinaryField()
#     publicKey = models.CharField(max_length=2000)

#     def __str__(self):
#         return f"{self.userName} - {self.group}"

class ExtraUserInfo(models.Model):
    username = models.CharField(max_length=64)
    isAdmin = models.BooleanField(default=False)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, blank=True)
    symKey = models.BinaryField()
    publicKey = models.CharField(max_length=2000)