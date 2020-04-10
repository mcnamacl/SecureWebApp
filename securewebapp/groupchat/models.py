from django.db import models

class Group(models.Model):
    groupName = models.CharField(max_length=64)

    def __str__(self):
        return f"{self.groupName}" 

class User(models.Model):
    userName = models.CharField(max_length=64)
    email = models.CharField(max_length=64)
    publicKey = models.CharField(max_length=1024)
    privateKey = models.CharField(max_length=1024)
    symKey = models.CharField(max_length=1024)
    group = models.ForeignKey(Group, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.userName} - {self.group}"