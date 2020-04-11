from django.shortcuts import render
from django.http import HttpResponse
from .models import Group, User, Message
import sys, os, base64

from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import binascii
from Crypto import Random

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

iv = Random.new().read(AES.block_size)


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

    mordor = User.objects.filter(group=1)
    theFellowship = User.objects.filter(group=2)

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

    newUser.publicKey = base64.encodestring(publicKey.exportKey())
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
        members =  User.objects.filter(group=2)

    context = {
        "signup" : True,
        "is_member" : is_member,
        "messages" : Group.objects.get(groupName="The Fellowship").messages.all(),
        "members" : members,
        "privatekey" : privateKey,
        "username" : name
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
            "username" : user.userName,
            "fellowshipMembers" : theFellowship,
            "mordorMembers" : mordor,
            "messages" : Group.objects.get(groupName="The Fellowship").messages.all()        
            }
        return render(request, "groupchat/adminpage.html", context)
    
    isFellowshipMember = False
    if user.symKey != "":
        isFellowshipMember = True

    members = []

    if isFellowshipMember:
        members = User.objects.filter(group=2)
    
    context = {
        "signup" : False,
        "is_member" : isFellowshipMember,
        "messages" : Group.objects.get(groupName="The Fellowship").messages.all(),
        "members" : members, 
        "username" : user.userName
    }
    return render(request, "groupchat/group.html", context)

def sendmsg(request):
    theFellowship = User.objects.filter(group=2)
    mordorMembers = User.objects.filter(group=1)

    msg = request.POST.get("msg")
    sender = request.POST.get("username")  

    user = User.objects.get(userName=sender)

    symKey = Group.objects.get(groupName="The Fellowship").currSymKey

    paddedMsg = pad(msg)
    
    cipher = AES.new(symKey, AES.MODE_CBC, iv)

    encryptedMsg = cipher.encrypt(paddedMsg.encode())

    message = Message(sender=sender, content=encryptedMsg)
    message.save()
    Group.objects.get(groupName="The Fellowship").messages.add(message)

    context = {
        "username" : user.userName,
        "fellowshipMembers" : theFellowship,
        "mordorMembers" : mordorMembers,
        "messages" : Group.objects.get(groupName="The Fellowship").messages.all()
    }
    return render(request, "groupchat/adminpage.html", context)

def getSymKey(user):
    privKey = RSA.importKey(open(user.userName + '_private_pem', 'r').read())

    decrypt = PKCS1_OAEP.new(key=privKey)

    symKey = decrypt.decrypt(user.symKey)
    return symKey

def updatesym(request):
    theFellowship = User.objects.filter(group=2)
    mordor = User.objects.filter(group=1)

    username = request.POST.get("username")

    oldSymKey = changesymkey()
    if oldSymKey != '':
        changeencryption(oldSymKey)

    context = {
        "username" : username,
        "fellowshipMembers" : theFellowship,
        "mordorMembers" : mordor,
        "messages" : Group.objects.get(groupName="The Fellowship").messages.all()      
          }

    return render(request, "groupchat/adminpage.html", context)


def changesymkey():
    theFellowship = User.objects.filter(group=2)
    theFellowshipGroup = Group.objects.get(groupName="The Fellowship")

    oldKey = theFellowshipGroup.currSymKey
    newKey = b'oneringtoruleall'
    theFellowshipGroup.currSymKey = newKey
    theFellowshipGroup.save()

    for member in theFellowship:
        pubkey = member.publicKey
        pubkey = RSA.importKey(base64.decodestring(pubkey))
        cipher = PKCS1_OAEP.new(pubkey)
        encryptedSymKey = cipher.encrypt(newKey)
        member.symKey = encryptedSymKey
        member.save()
    return oldKey

def addtofellowship(request):
    username = request.POST.get("username")

    theFellowship = User.objects.filter(group=2)
    mordor = User.objects.filter(group=1)

    user = User.objects.get(userName=username)
    user.group = Group.objects.get(groupName="The Fellowship")

    currSymKey = Group.objects.get(groupName="The Fellowship").currSymKey

    pubkey = user.publicKey
    pubkey = RSA.importKey(base64.decodestring(pubkey))
    cipher = PKCS1_OAEP.new(pubkey)
    encryptedSymKey = cipher.encrypt(currSymKey)
    user.symKey = encryptedSymKey
    user.save()

    context = {
        "fellowshipMembers" : theFellowship,
        "mordorMembers" : mordor,
        "messages" : Group.objects.get(groupName="The Fellowship").messages.all()      
          }
    return render(request, "groupchat/adminpage.html", context)

def removefromfellowship(request):
    username = request.POST.get("username")

    theFellowship = User.objects.filter(group=2)
    mordor = User.objects.filter(group=1)

    user = User.objects.get(userName=username)
    user.group = Group.objects.get(groupName="Mordor")
    user.save()

    changeencryption()

    context = {
        "fellowshipMembers" : theFellowship,
        "mordorMembers" : mordor,
        "messages" : Group.objects.get(groupName="The Fellowship").messages.all()      
          }
    return render(request, "groupchat/adminpage.html", context)

def decodemsgs(request):
    privKey = request.POST.get("privkey")
    username = request.POST.get("username")

    user = User.objects.get(userName=username)

    symKey = getSymKey(user)

    theFellowship = User.objects.filter(group=2)
    mordor = User.objects.filter(group=1)

    theFellowshipGroup = Group.objects.get(groupName="The Fellowship")

    decryptedMessages = []

    cipher = AES.new(theFellowshipGroup.currSymKey, AES.MODE_CBC, iv)

    for message in theFellowshipGroup.messages.all():
        print(message.content, file=sys.stderr)
        msg = cipher.decrypt(message.content)
        print(msg, file=sys.stderr)
        decryptedMessages.append(msg)

    context = {
        "signup" : False,
        "is_member" : True,
        "messages" : decryptedMessages,
        "members" : theFellowship,
        "privatekey" : "",
        "username" : username
    }
    return render(request, "groupchat/group.html", context)

def changeencryption(oldSymKey):
    newMessages = []
    messages = Group.objects.get(groupName="The Fellowship").messages.all()
    # symKey = Group.objects.get(groupName="The Fellowship").currSymKey
    cipher = AES.new(oldSymKey, AES.MODE_CBC, iv)

    for message in messages:
        msg = cipher.decrypt(message.content)
        print(msg, file=sys.stderr)