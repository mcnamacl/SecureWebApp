# Generated by Django 3.0.5 on 2020-04-11 19:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('groupchat', '0004_auto_20200411_2022'),
    ]

    operations = [
        migrations.AlterField(
            model_name='group',
            name='currSymKey',
            field=models.BinaryField(),
        ),
    ]