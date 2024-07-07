from rest_framework import serializers

from user_manager.models import User, Organisation


class RegisterUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email', 'password', 'firstName', 'lastName', 'lastName', 'phone')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            firstName=validated_data['firstName'],
            lastName=validated_data['lastName'],
            email=validated_data['email'],
            phone=validated_data.get('phone', '')
        )
        user.set_password(validated_data['password'])

        org = Organisation.objects.create(
            name=f"{user.first_name}'s Organisation"
        )
        org.users.add(user)
        org.save()
        return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('userId', 'email', 'firstName', 'lastName', 'lastName', 'phone')


class OrganisationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organisation
        fields = ['orgId', 'name', 'description']
