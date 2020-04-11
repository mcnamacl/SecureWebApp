from django.db import models

class Message(models.Model):
    sender = models.CharField(max_length=64)
    content = models.CharField(max_length=10000)

    def __str__(self):
        return f"{self.content}"

class Group(models.Model):
    groupName = models.CharField(max_length=64)
    messages = models.ManyToManyField(Message, related_name="group", blank=True)

    def __str__(self):
        return f"{self.groupName}" 

class User(models.Model):
    userName = models.CharField(max_length=64)
    email = models.CharField(max_length=64, default="")
    publicKey = models.CharField(max_length=1024)
    privateKey = models.CharField(max_length=1024)
    symKey = models.CharField(max_length=1024, default="")
    isAdmin = models.BooleanField(default=False)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, blank=True)

    def __str__(self):
        return f"{self.userName} - {self.group}"