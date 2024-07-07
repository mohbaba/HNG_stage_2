import uuid

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models


# Create your models here.

class UserManager(BaseUserManager):

    def create_user(self, firstName, lastName, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(firstName=firstName, lastName=lastName, email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user


class User(AbstractBaseUser):
    userId = models.AutoField(primary_key=True)
    firstName = models.CharField(max_length=50, blank=False, null=False)
    lastName = models.CharField(max_length=50, blank=False, null=False)
    email = models.EmailField(unique=True, blank=False, null=False)
    phone = models.CharField(max_length=50, blank=True, null=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    # USER_ID_FIELD = 'userId'
    REQUIRED_FIELDS = ['firstName', 'lastName']

    def __str__(self):
        return self.email


class Organisation(models.Model):
    orgId = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50, blank=False, null=False)
    description = models.TextField()
    members = models.ManyToManyField(User, related_name='organisations')

    def __str__(self):
        return self.name
