from django.contrib.auth import authenticate
from django.shortcuts import render, get_object_or_404
import logging

from django.utils.crypto import get_random_string
from rest_framework import status
from rest_framework.exceptions import PermissionDenied
from rest_framework.generics import RetrieveAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from user_manager.models import User, Organisation
from user_manager.serializers import RegisterUserSerializer, UserSerializer, OrganisationSerializer


# Create your views here.

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class RegisterUserView(APIView):

    def post(self, request):
        serializer = RegisterUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            tokens = get_tokens_for_user(user)
            response = {
                'status': 'success',
                'message': 'Registration successful',
                'data': {
                    'accessToken': tokens['access'],
                    'user': UserSerializer(user).data,

                }
            }
            return Response(response, status=status.HTTP_201_CREATED)
        unsuccessful_response = {
            'status': 'Bad Request',
            'message': 'Registration unsuccessful',
            'status_code': status.HTTP_400_BAD_REQUEST
        }
        return Response(unsuccessful_response, status=status.HTTP_422_UNPROCESSABLE_ENTITY)


class LoginUserView(APIView):

    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = authenticate(email=email, password=password)
        if user is not None:
            tokens = get_tokens_for_user(user)
            response = {
                'status': 'success',
                'message': 'Login successful',
                'data': {
                    'accessToken': tokens['access'],
                    'user': UserSerializer(user).data,
                }
            }
            return Response(response, status=status.HTTP_200_OK)

        bad_request = {
            "status": "Bad Request",
            "message": "Authentication failed",
            "statusCode": status.HTTP_401_UNAUTHORIZED
        }
        return Response(bad_request, status=status.HTTP_401_UNAUTHORIZED)


class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, userId):
        user = get_object_or_404(User, userId=userId)
        if request.user != user:
            return Response({
                "status": "Bad Request",
                "message": "You do not have permission to access this user's details.",
                "statusCode": status.HTTP_403_FORBIDDEN

            }, status=status.HTTP_403_FORBIDDEN)

        serializer = UserSerializer(user)
        return Response({
            "status": "success",
            "message": "User details retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)


class UserOrganisationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        # saved_user = User.objects.get()
        organisations = Organisation.objects.filter(members__email=user.email)
        serializer = OrganisationSerializer(organisations, many=True)
        return Response({
            "status": "success",
            "message": "Organisations retrieved successfully",
            "data": {
                "organisations": serializer.data
            }
        }, status=status.HTTP_200_OK)


class GetOrganisationView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, orgId):
        try:
            organisation = Organisation.objects.get(orgId=orgId)
        except Organisation.DoesNotExist:
            return Response({
                "status": "error",
                "message": "Organisation not found or access denied",
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = OrganisationSerializer(organisation)
        return Response({
            "status": "success",
            "message": "Organisation retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

class AddUserToOrganisationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, orgId):
        try:
            organisation = Organisation.objects.get(orgId=orgId, members=request.user)
        except Organisation.DoesNotExist:
            return Response({
                "status": "error",
                "message": "Organisation not found or access denied",
            }, status=status.HTTP_404_NOT_FOUND)

        user_id = request.data.get("userId")
        try:
            user = User.objects.get(userId=user_id)
        except User.DoesNotExist:
            return Response({
                "status": "error",
                "message": "User not found",
            }, status=status.HTTP_404_NOT_FOUND)

        organisation.members.add(user)
        return Response({
            "status": "success",
            "message": "User added to organisation successfully"
        }, status=status.HTTP_200_OK)


class CreateOrganisationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = OrganisationSerializer(data=request.data)
        if serializer.is_valid():
            organisation = serializer.save()
            organisation.users.add(request.user)
            return Response({
                'status': 'success',
                'message': 'Organisation created successfully',
                'data': OrganisationSerializer(organisation).data
            }, status=status.HTTP_201_CREATED)
        return Response({
            'status': 'Bad Request',
            'message': 'Client error',
            'statusCode': 400
        }, status=status.HTTP_400_BAD_REQUEST)