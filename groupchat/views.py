from django.shortcuts import render
from django.http import HttpResponse
from .models import Group, GroupUser, Message
import sys, os, base64, re

from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
from Crypto import Random

from .simple_aes_cipher import AESCipher

def index(request):
    return render(request, "groupchat/login.html")

def signup_show(request):
    return render(request, "groupchat/signup.html")

def login_show(request):
    return render(request, "groupchat/login.html")

def login_as_admin_show(request):
    return render(request, "groupchat/adminpage.html")

def signup(request):
    name = request.POST.get("name", "")
    email = request.POST.get("email", "")

    if name == "Claire":
        mordor = Group()
        fellowship = Group()
        mordor.groupName = "Mordor"
        fellowship.groupName = "The Fellowship"
        fellowship.currSymKey = os.urandom(16)
        mordor.save()
        fellowship.save()

    newUser = GroupUser()
    newUser.userName = name

    mordor = GroupUser.objects.filter(group=1)
    theFellowship = GroupUser.objects.filter(group=2)

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

    newUser.publicKey = publicKey.exportKey().decode()

    privateKey = privateKey.exportKey().decode()
    with open(newUser.userName + '_private_pem', 'w') as pr:
        pr.write(privateKey)

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
        context = {
        "messages" : getencryptedmessages()   ,
        "fellowshipMembers" : GroupUser.objects.filter(group=2),
        "mordorMembers" : GroupUser.objects.filter(group=1),
        "username" : name
        }
        return render(request, "groupchat/adminpage.html", context)

    context = {
        "signup" : True,
        "is_member" : is_member,
        "messages" : getencryptedmessages()   ,
        "members" : members,
        "username" : name
    }
    return render(request, "groupchat/group.html", context)

def login(request):
    name = request.POST.get("name", "")
    email = request.POST.get("email", "")

    user = GroupUser.objects.get(userName=name)
    
    theFellowship = GroupUser.objects.filter(group=2)
    mordor = GroupUser.objects.filter(group=1)

    if user.isAdmin:
        context = {
            "username" : user.userName,
            "fellowshipMembers" : theFellowship,
            "mordorMembers" : mordor,
            "messages" : getencryptedmessages(),
            "username" : name          
            }
        return render(request, "groupchat/adminpage.html", context)
    
    isFellowshipMember = False
    if user.group == Group.objects.get(groupName="The Fellowship"):
        isFellowshipMember = True

    members = []

    if isFellowshipMember:
        members = GroupUser.objects.filter(group=2)
    
    context = {
        "signup" : False,
        "is_member" : isFellowshipMember,
        "messages" : getencryptedmessages(),
        "fellowshipMembers" : members, 
        "username" : user.userName
    }
    return render(request, "groupchat/group.html", context)

def sendmsg(request):
    theFellowship = GroupUser.objects.filter(group=2)
    mordorMembers = GroupUser.objects.filter(group=1)

    msg = request.POST.get("msg")
    sender = request.POST.get("username")  

    user = GroupUser.objects.get(userName=sender)

    # using user get symkey
    symKey = getSymKey(user)    
    cipher = AESCipher(symKey)

    encryptedMsg = cipher.encrypt(msg)

    message = Message(sender=sender, content=encryptedMsg)
    message.save()
    Group.objects.get(groupName="The Fellowship").messages.add(message)

    context = {
        "username" : user.userName,
        "fellowshipMembers" : theFellowship,
        "mordorMembers" : mordorMembers,
        "messages" : getencryptedmessages(),
        "is_member" : True
    }
    if user.isAdmin:
        return render(request, "groupchat/adminpage.html", context)

    return render(request, "groupchat/group.html", context)

def getSymKey(user):
    privKey = RSA.importKey(open(user.userName + '_private_pem', 'r').read())

    decrypt = PKCS1_OAEP.new(key=privKey)

    symKey = decrypt.decrypt(user.symKey)

    return symKey

def updatesym(request):
    theFellowship = GroupUser.objects.filter(group=2)
    mordor = GroupUser.objects.filter(group=1)

    username = request.POST.get("username")

    oldSymKey = changesymkey()

    if oldSymKey != '':
        changeencryption(oldSymKey)

    context = {
        "username" : username,
        "fellowshipMembers" : theFellowship,
        "mordorMembers" : mordor,
        "messages" : getencryptedmessages()      
        }

    return render(request, "groupchat/adminpage.html", context)

def getencryptedmessages():
    content = []
    senders = []

    for message in Group.objects.get(groupName="The Fellowship").messages.all():
        content.append(message.content)
        senders.append(message.sender)

    return zip(content, senders)

def changesymkey():
    theFellowship = GroupUser.objects.filter(group=2)
    theFellowshipGroup = Group.objects.get(groupName="The Fellowship")

    oldKey = theFellowshipGroup.currSymKey
    newKey = os.urandom(16)
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

    theFellowship = GroupUser.objects.filter(group=2)
    mordor = GroupUser.objects.filter(group=1)

    user = GroupUser.objects.get(userName=otheruser)
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

    theFellowship = GroupUser.objects.filter(group=2)
    mordor = GroupUser.objects.filter(group=1)

    user = GroupUser.objects.get(userName=otheruser)
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

    user = GroupUser.objects.get(userName=username)
    symKey = getSymKey(user)

    theFellowship = GroupUser.objects.filter(group=2)
    mordor = GroupUser.objects.filter(group=1)

    theFellowshipGroup = Group.objects.get(groupName="The Fellowship")

    content = []
    senders = []

    cipher = AESCipher(symKey)

    for message in theFellowshipGroup.messages.all():
        msg = cipher.decrypt(message.content)
        content.append(msg)
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
    cipherOld = AESCipher(oldSymKey)
    cipherNew = AESCipher(symKey)

    # new cipher with new symkey

    for message in messages:
        msg = cipherOld.decrypt(message.content)
        message.content = cipherNew.encrypt(msg)
        message.save()
    return