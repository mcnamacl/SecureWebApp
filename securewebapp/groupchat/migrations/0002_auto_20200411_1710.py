# Generated by Django 3.0.5 on 2020-04-11 16:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('groupchat', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='publicKey',
            field=models.BinaryField(),
        ),
    ]
