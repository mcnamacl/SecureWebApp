from django.db import models

class Message(models.Model):
    sender = models.CharField(max_length=64)
    content = models.CharField(max_length=10000)

    def __str__(self):
        return f"{self.content}"

class User(models.Model):
    userName = models.CharField(max_length=64)
    email = models.CharField(max_length=64, default="")
    publicKey = models.CharField(max_length=1024)
    privateKey = models.CharField(max_length=1024)
    symKey = models.CharField(max_length=1024)

    def __str__(self):
        return f"{self.userName} - {self.group}"

class Group(models.Model):
    groupName = models.CharField(max_length=64)
    messages = models.ManyToManyField(Message, related_name="group")
    members = models.ManyToManyField(User, related_name="group")

    def __str__(self):
        return f"{self.groupName}" 