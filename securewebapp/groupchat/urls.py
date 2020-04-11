from django.urls import path
from . import views

urlpatterns = [
    path("", views.index),
    path("signup_show", views.signup_show, name="signup_show"),
    path("login_show", views.login_show, name="login_show"),
    path("login", views.login, name="login"),
    path("signup", views.signup, name="signup"),
]