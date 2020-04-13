from django.shortcuts import render
from django.http import Http404, HttpResponse, HttpResponseRedirect
from .models import Group, ExtraUserInfo, Message
import sys, os, base64, re

from django.contrib.auth.models import User

from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
from Crypto import Random

from cryptography.fernet import Fernet
from django.urls import reverse
from django.contrib.auth import authenticate

def index(request):
    return render(request, "groupchat/adminsignup.html")

def signup_show(request):
    return render(request, "groupchat/signup.html")

def login_show(request):
    return render(request, "groupchat/login.html")

def login_as_admin_show(request):
    return render(request, "groupchat/adminpage.html")

def adminsignup(request):
    name = request.POST.get("name", "")
    password = request.POST.get("password", "")

    user = User.objects.create_user(username=name,
                                 password=password)
    
    user.save()

    newUser = ExtraUserInfo()
    newUser.username = name
    
    mordor = Group()
    fellowship = Group()
    mordor.groupName = "Mordor"
    fellowship.groupName = "The Fellowship"
    fellowship.currSymKey = Fernet.generate_key()
    mordor.save()
    fellowship.save()

    privateKey = RSA.generate(1024)
    publicKey = privateKey.publickey()

    newUser.publicKey = publicKey.exportKey().decode()

    # privateKey = privateKey.exportKey().decode()
    # with open(newUser.username + '_private_pem', 'w') as pr:
    #     pr.write(privateKey)

    newUser.privateKey = privateKey.exportKey().decode()

    publicKey = RSA.importKey(newUser.publicKey)
    cipher = PKCS1_OAEP.new(publicKey)
    encryptedSymKey = cipher.encrypt(Group.objects.get(groupName="The Fellowship").currSymKey)
    newUser.symKey = encryptedSymKey
    newUser.group = Group.objects.get(groupName="The Fellowship")
    newUser.isAdmin = True

    is_member = True

    newUser.save()

    context = {
        "messages" : getencryptedmessages()   ,
        "fellowshipMembers" : ExtraUserInfo.objects.filter(group=2),
        "mordorMembers" : ExtraUserInfo.objects.filter(group=1),
        "username" : name
        }

    return render(request, "groupchat/adminpage.html", context)

def signup(request):
    name = request.POST.get("name", "")
    password = request.POST.get("password", "")

    newUser = ExtraUserInfo()

    user = User.objects.create_user(username=name,
                                 password=password)

    user.save()

    newUser = ExtraUserInfo()
    newUser.username = name

    mordor = ExtraUserInfo.objects.filter(group=1)
    theFellowship = ExtraUserInfo.objects.filter(group=2)

    alreadyExists = False

    for user in mordor:
        if user.username == name:
            alreadyExists = True
    
    if alreadyExists:
        return render(request, "groupchat/signup.html", {"message": "Username already exists."})
    
    for member in theFellowship:
        if member.username == name:
            alreadyExists = True
    
    if alreadyExists:
        return render(request, "groupchat/signup.html", {"message": "Username already exists."})

    privateKey = RSA.generate(1024)
    publicKey = privateKey.publickey()

    newUser.publicKey = publicKey.exportKey().decode()

    privateKey = privateKey.exportKey().decode()
    with open(newUser.username + '_private_pem', 'w') as pr:
        pr.write(privateKey)

    is_member = False

    members = []

    newUser.group = Group.objects.get(groupName="Mordor")
    
    newUser.save()

    context = {
        "signup" : True,
        "is_member" : is_member,
        "messages" : getencryptedmessages()   ,
        "members" : members,
        "username" : name
    }
    return render(request, "groupchat/group.html", context)

def login(request):
    username = request.POST.get("name", "")
    password = request.POST.get("password", "")
    
    theFellowship = ExtraUserInfo.objects.filter(group=2)
    mordor = ExtraUserInfo.objects.filter(group=1)

    exists = False

    u = User.objects.filter(username=username)

    correct = u[0].check_password(password)
    
    if not correct:
        return render(request, "login.html", {"message": "Invalid credentials."})

    userinfo = ExtraUserInfo.objects.get(username=username)

    if userinfo.isAdmin:
        context = {
            "username" : userinfo.username,
            "fellowshipMembers" : theFellowship,
            "mordorMembers" : mordor,
            "messages" : getencryptedmessages(),
            "username" : username          
            }
        return render(request, "groupchat/adminpage.html", context)
    
    isFellowshipMember = False
    if userinfo.group == Group.objects.get(groupName="The Fellowship"):
        isFellowshipMember = True

    members = []

    if isFellowshipMember:
        members = ExtraUserInfo.objects.filter(group=2)
    
    context = {
        "signup" : False,
        "is_member" : isFellowshipMember,
        "messages" : getencryptedmessages(),
        "fellowshipMembers" : members, 
        "username" : username
    }
    return render(request, "groupchat/group.html", context)

def sendmsg(request):
    theFellowship = ExtraUserInfo.objects.filter(group=2)
    mordorMembers = ExtraUserInfo.objects.filter(group=1)

    msg = request.POST.get("msg")
    sender = request.POST.get("username")  

    user = ExtraUserInfo.objects.get(username=sender)

    # using user get symkey
    symKey = getSymKey(user)    
    cipher = Fernet(symKey)

    encryptedMsg = cipher.encrypt(msg.encode())

    message = Message(sender=sender, content=encryptedMsg)
    message.save()
    Group.objects.get(groupName="The Fellowship").messages.add(message)

    context = {
        "username" : user.username,
        "fellowshipMembers" : theFellowship,
        "mordorMembers" : mordorMembers,
        "messages" : getencryptedmessages(),
        "is_member" : True
    }
    if user.isAdmin:
        return render(request, "groupchat/adminpage.html", context)

    return render(request, "groupchat/group.html", context)

def getSymKey(user):
    # privKey = RSA.importKey(open(user.username + '_private_pem', 'r').read())
    privKey = RSA.importKey(user.privateKey)

    decrypt = PKCS1_OAEP.new(key=privKey)

    symKey = decrypt.decrypt(user.symKey)

    return symKey

def getencryptedmessages():
    content = []
    senders = []

    for message in Group.objects.get(groupName="The Fellowship").messages.all():
        content.append((message.content).tobytes().decode())
        senders.append(message.sender)

    return zip(content, senders)

def changesymkey():
    theFellowship = ExtraUserInfo.objects.filter(group=2)
    theFellowshipGroup = Group.objects.get(groupName="The Fellowship")

    oldKey = theFellowshipGroup.currSymKey
    newKey = Fernet.generate_key()
    theFellowshipGroup.currSymKey = newKey
    theFellowshipGroup.save()

    for member in theFellowship:
        pubkey = member.publicKey
        pubkey = RSA.importKey(pubkey)
        cipher = PKCS1_OAEP.new(pubkey)
        encryptedSymKey = cipher.encrypt(newKey)
        member.symKey = encryptedSymKey
        member.save()
    return oldKey

def addtofellowship(request):
    otheruser = request.POST.get("otheruser")

    theFellowship = ExtraUserInfo.objects.filter(group=2)
    mordor = ExtraUserInfo.objects.filter(group=1)

    user = ExtraUserInfo.objects.get(username=otheruser)
    user.group = Group.objects.get(groupName="The Fellowship")

    currSymKey = Group.objects.get(groupName="The Fellowship").currSymKey

    pubkey = user.publicKey
    pubkey = RSA.importKey(pubkey)
    cipher = PKCS1_OAEP.new(pubkey)
    encryptedSymKey = cipher.encrypt(currSymKey)
    user.symKey = encryptedSymKey
    user.save()

    context = {
        "fellowshipMembers" : theFellowship,
        "mordorMembers" : mordor,
        "messages" : getencryptedmessages(),
        "username" : "Claire"      
        }
    return render(request, "groupchat/adminpage.html", context)

def removefromfellowship(request):
    otheruser = request.POST.get("otheruser")

    theFellowship = ExtraUserInfo.objects.filter(group=2)
    mordor = ExtraUserInfo.objects.filter(group=1)

    user = ExtraUserInfo.objects.get(username=otheruser)
    user.group = Group.objects.get(groupName="Mordor")
    user.save()

    oldSymKey = changesymkey()
    changeencryption(oldSymKey)

    context = {
        "fellowshipMembers" : theFellowship,
        "mordorMembers" : mordor,
        "messages" : getencryptedmessages(),
        "username" : "Claire"      
        }
    return render(request, "groupchat/adminpage.html", context)

def decodemsgs(request):
    username = request.POST.get("username")

    user = ExtraUserInfo.objects.get(username=username)
    symKey = getSymKey(user)

    theFellowship = ExtraUserInfo.objects.filter(group=2)
    mordor = ExtraUserInfo.objects.filter(group=1)

    theFellowshipGroup = Group.objects.get(groupName="The Fellowship")

    content = []
    senders = []

    cipher = Fernet(symKey)

    for message in theFellowshipGroup.messages.all():
        msg = cipher.decrypt((message.content).tobytes())
        content.append(msg.decode())
        senders.append(message.sender)

    if user.isAdmin:
        context = {
            "is_member" : True,
            "messages" : zip(content, senders),
            "fellowshipMembers" : theFellowship,
            "mordorMembers" : mordor,
            "username" : username
        }
        return render(request, "groupchat/adminpage.html", context)
        
    context = {
        "is_member" : True,
        "messages" : zip(content, senders),
        "fellowshipMembers" : theFellowship,
        "username" : username
    }

    return render(request, "groupchat/group.html", context)

def changeencryption(oldSymKey):
    newMessages = []
    messages = Group.objects.get(groupName="The Fellowship").messages.all()
    symKey = Group.objects.get(groupName="The Fellowship").currSymKey
    cipherOld = Fernet(oldSymKey)
    cipherNew = Fernet(symKey)

    # new cipher with new symkey

    for message in messages:
        msg = cipherOld.decrypt((message.content).tobytes())
        message.content = cipherNew.encrypt(msg)
        message.save()
    return