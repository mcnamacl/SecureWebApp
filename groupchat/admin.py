from django.contrib import admin

from .models import Group, Message

# admin.site.register(GroupUser)
admin.site.register(Group)
admin.site.register(Message)