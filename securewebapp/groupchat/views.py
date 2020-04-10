from django.shortcuts import render
from django.http import HttpResponse
from .models import Group, User, Message
import sys

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii


def index(request):
    return render(request, "groupchat/index.html")

def signup_show(request):
    return render(request, "groupchat/signup.html")

def login_show(request):
    return render(request, "groupchat/login.html")

def signup(request):
    name = request.GET.get("name", "")
    email = request.GET.get("email", "")

    newUser = User()
    newUser.userName = name

    mordor = Group.objects.get(groupName="Mordor") 
    theFellowship = Group.objects.get(groupName="The Fellowship") 

    alreadyExists = False

    for member in mordor.members.all():
        if member.userName == name:
            alreadyExists = True
    
    if alreadyExists:
        return render(request, "groupchat/signup.html", {"message": "Username already exists."})
    
    for member in theFellowship.members.all():
        if member.userName == name:
            alreadyExists = True
    
    if alreadyExists:
        return render(request, "groupchat/signup.html", {"message": "Username already exists."})

    newUser.email = email

    privateKey = RSA.generate(1024)
    publicKey = privateKey.publickey()

    privatePem = privateKey.export_key().decode()
    publicPem = publicKey.export_key().decode()

    newUser.publicKey = privatePem
    newUser.privateKey = publicPem

    newUser.save()

    mordor.members.add(newUser)

    officialgroup = Group.objects.all()[0]

    context = {
        "is_member" : "false",
        "messages" : officialgroup.messages.all()
    }

    return render(request, "groupchat/group.html")

def login(request):
    name = request.GET.get("name", "")
    email = request.GET.get("email", "")

    user = User.objects.get(userName=name)
    print(user.email, file=sys.stderr)

    return render(request, "groupchat/group.html")

def login_as_admin(request):
    return render(request, "groupchat/adminpage.html")