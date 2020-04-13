from django.contrib import admin

from .models import ExtraUserInfo, Group

admin.site.register(ExtraUserInfo)
admin.site.register(Group)