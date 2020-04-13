from django.urls import path
from . import views

urlpatterns = [
    path("", views.index),
    path("signup_show", views.signup_show, name="signup_show"),
    path("login_show", views.login_show, name="login_show"),
    path("login", views.login, name="login"),
    path("signup", views.signup, name="signup"),
    path("adminsignup", views.adminsignup, name="adminsignup"),
    path("sendmsg", views.sendmsg, name="sendmsg"),
    path("updatesym", views.updatesym, name="updatesym"),
    path("addtofellowship", views.addtofellowship, name="addtofellowship"),
    path("removefromfellowship", views.removefromfellowship, name="removefromfellowship"),
    path("decodemsgs", views.decodemsgs, name="decodemsgs")
]