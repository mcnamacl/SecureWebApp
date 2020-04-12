from django.contrib import admin

from .models import GroupUser, Group

admin.site.register(GroupUser)
admin.site.register(Group)