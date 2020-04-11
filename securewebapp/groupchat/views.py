from django.shortcuts import render
from django.http import HttpResponse
from .models import Group, User, Message
import sys, os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
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

    private = privateKey.exportKey().decode()
    public = publicKey.exportKey().decode()

    newUser.publicKey = public

    is_member = False

    members = []

    if name == "Claire":
        newUser.group = Group.objects.get(groupName="The Fellowship")
        newUser.isAdmin = True
        is_member = True
    else:
        newUser.group = Group.objects.get(groupName="Mordor")

    newUser.save()

    if name == "Claire":
        members =  User.objects.filter(group=2)

    context = {
        "signup" : True,
        "is_member" : is_member,
        "messages" : Group.objects.get(groupName="The Fellowship").messages.all(),
        "members" : members,
        "privatekey" : privateKey
    }

    return render(request, "groupchat/group.html", context)

def login(request):
    name = request.GET.get("name", "")
    email = request.GET.get("email", "")

    user = User.objects.get(userName=name)
    
    theFellowship = User.objects.filter(group=2)
    mordor = User.objects.filter(group=1)

    if user.isAdmin:
        context = {
            "fellowshipMembers" : theFellowship,
            "mordorMembers" : mordor,
            "messages" : Group.objects.get(groupName="The Fellowship").messages.all()        }
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
        "signup" : True,
        "is_member" : isFellowshipMember,
        "messages" : messages,
        "members" : members, 
        "username" : user.userName
    }
    return render(request, "groupchat/group.html", context)

def sendmsg(request):
    theFellowship = User.objects.filter(group=2)
    mordorMembers = User.objects.filter(group=1)

    msg = request.POST.get("msg")
    sender = request.user
    message = Message(sender=sender, content=msg)
    message.save()
    Group.objects.get(groupName="The Fellowship").messages.add(message)

    context = {
        "fellowshipMembers" : theFellowship,
        "mordorMembers" : mordorMembers,
        "messages" : Group.objects.get(groupName="The Fellowship").messages.all()
    }
    return render(request, "groupchat/adminpage.html", context)

def updatesym(request):
    theFellowship = User.objects.filter(group=2)
    mordor = User.objects.filter(group=1)

    theFellowshipGroup = Group.objects.get("The Fellowship")

    newKey = os.urandom(16)
    theFellowshipGroup.currSymKey = newKey

    for member in theFellowship:
        pubkey = member.pubkey
        pubkey = pubkey.encode()
        cipher = PKCS1_OAEP.new(key=pubkey)
        encryptedSymKey = cipher.encrypt(newKey)
        member.symKey = encryptedSymKey.decode()

    context = {
        "fellowshipMembers" : theFellowship,
        "mordorMembers" : mordor,
        "messages" : Group.objects.get(groupName="The Fellowship").messages.all()      
          }

    return render(request, "groupchat/adminpage.html", context)

def addUserToFellowship(request):
    return render(request, "groupchat/adminpage.html")

def decodeMessage(encodedMsg):
    return