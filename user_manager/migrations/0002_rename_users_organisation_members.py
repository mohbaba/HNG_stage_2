# Generated by Django 5.0.6 on 2024-07-07 19:10

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('user_manager', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='organisation',
            old_name='users',
            new_name='members',
        ),
    ]
