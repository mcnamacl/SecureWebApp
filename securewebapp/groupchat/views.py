from django.shortcuts import render
from django.http import HttpResponse
from .models import Group, User
import sys

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii


def index(request):
    return render(request, "groupchat/index.html")

def signup_show(request):
    return render(request, "groupchat/signup.html")

def login_show(request):
    return render(request, "groupchat/signup.html")

def signup(request):
    name = request.GET.get("name", "")
    email = request.GET.get("email", "")

    newUser = User()
    newUser.userName = name
    newUser.email = email

    privateKey = RSA.generate(1024)
    publicKey = privateKey.publickey()

    privatePem = privateKey.export_key().decode()
    publicPem = publicKey.export_key().decode()

    newUser.publicKey = privatePem
    newUser.privateKey = publicPem

    newUser.group = Group.objects.all()[0]

    newUser.save()

    return render(request, "groupchat/signup.html")

def login(request):
    name = request.GET.get("name", "")
    email = request.GET.get("email", "")

    return render(request, "groupchat/group.html")