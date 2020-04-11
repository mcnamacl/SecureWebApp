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

def login_as_admin_show(request):
    return render(request, "groupchat/adminpage.html")

def signup(request):
    name = request.GET.get("name", "")
    email = request.GET.get("email", "")

    newUser = User()
    newUser.userName = name

    mordor = User.objects.filter(group=0)
    theFellowship = User.objects.filter(group=1)

    alreadyExists = False

    for user in mordor:
        if user.userName == name:
            alreadyExists = True
    
    if alreadyExists:
        return render(request, "groupchat/signup.html", {"message": "Username already exists."})
    
    for member in theFellowship:
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

    is_member = False

    members = []

    if name == "Claire":
        newUser.group = Group.objects.get(groupName="The Fellowship")
        newUser.isAdmin = True
        is_member = True
        newUser.symKey = "lmao"
    else:
        newUser.group = Group.objects.get(groupName="Mordor")

    newUser.save()

    if name == "Claire":
        members =  User.objects.filter(group=2)
        print(members, file=sys.stderr)


    context = {
        "is_member" : is_member,
        "messages" : Group.objects.get(groupName="The Fellowship").messages.all(),
        "members" : members
    }

    return render(request, "groupchat/group.html")

def login(request):
    name = request.GET.get("name", "")
    email = request.GET.get("email", "")

    user = User.objects.get(userName=name)
    
    theFellowship = User.objects.filter(group=2)
    print(type(theFellowship), file=sys.stderr)
    mordorMembers = User.objects.filter(group=1)

    if user.isAdmin:
        context = {
            "fellowshipMembers" : theFellowship,
            "mordorMembers" : mordorMembers
        }
        return render(request, "groupchat/adminpage.html", context)
    
    isFellowshipMember = False
    if user.symKey != "":
        isFellowshipMember = True

    messages = []

    for msg in Group.objects.get(groupName="The Fellowship").messages.all():
        if isFellowshipMember:
            msg = decodeMessage(msg.content, user.publicKey, user.privateKey, user.symKey)
        messages.append(msg)

    members = []

    if isFellowshipMember:
        members = User.objects.filter(group=2)
    
    context = {
        "is_member" : isFellowshipMember,
        "messages" : messages,
        "members" : members
    }
    return render(request, "groupchat/group.html", context)

def addUserToFellowship(request):
    return render(request, "groupchat/adminpage.html")

def decodeMessage(encodedMsg):
    return