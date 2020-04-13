# Generated by Django 3.0.5 on 2020-04-13 15:46

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Message',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sender', models.CharField(max_length=64)),
                ('content', models.BinaryField()),
            ],
        ),
        migrations.CreateModel(
            name='Group',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('groupName', models.CharField(max_length=64)),
                ('currSymKey', models.BinaryField()),
                ('messages', models.ManyToManyField(blank=True, related_name='group', to='groupchat.Message')),
            ],
        ),
        migrations.CreateModel(
            name='ExtraUserInfo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=64)),
                ('isAdmin', models.BooleanField(default=False)),
                ('symKey', models.BinaryField()),
                ('publicKey', models.CharField(max_length=2000)),
                ('group', models.ForeignKey(blank=True, on_delete=django.db.models.deletion.CASCADE, to='groupchat.Group')),
            ],
        ),
    ]