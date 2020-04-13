from django.db import models
import base64

class Message(models.Model):
    sender = models.CharField(max_length=64)
    content = models.CharField(max_length=64)

    def __str__(self):
        return f"{self.content}"

class Group(models.Model):
    groupName = models.CharField(max_length=64)
    messages = models.ManyToManyField(Message, related_name="group", blank=True)
    currSymKey = models.BinaryField()

    def __str__(self):
        return f"{self.groupName}" 

class GroupUser(models.Model):
    userName = models.CharField(max_length=64)
    email = models.CharField(max_length=64, default="")
    isAdmin = models.BooleanField(default=False)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, blank=True)
    symKey = models.BinaryField()
    publicKey = models.CharField(max_length=2000)

    def __str__(self):
        return f"{self.userName} - {self.group}"