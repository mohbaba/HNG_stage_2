from django.core.handlers.wsgi import WSGIRequest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient, APIRequestFactory
from rest_framework_simplejwt.tokens import RefreshToken

from user_manager.models import User, Organisation


# Create your tests here.


class TestUserManager(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('register')
        self.user_data = {"firstName": "John",
                          "lastName": "Doe",
                          "email": "johnDoe@email.com",
                          "password": "password",
                          "phone": "0812345678"}
        self.user = User.objects.create_user(
            # userId="another_user_id",
            firstName="Jane",
            lastName="Smith",
            email="jane.smith@example.com",
            password="password123",
            phone="0987654321"
        )
        self.tokens = RefreshToken.for_user(self.user)

    def test_register_user(self):
        url = reverse('register')
        data = {"firstName": "John", "lastName": "Doe", "email": "johnDoe@email.com", "password": "password",
                "phone": "0812345678"}
        response = self.client.post(url, data, format='json')
        print(response.data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 2)

        self.assertEqual(response.data['data']['user']['email'], "johnDoe@email.com")
        user = User.objects.get(email="johnDoe@email.com")
        self.assertIsNotNone(user)
        self.assertTrue(user.check_password("password"))

    def test_register_user_missing_fields(self):
        invalid_data = self.user_data.copy()
        invalid_data.pop('firstName')
        response = self.client.post(self.register_url, invalid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)

    def test_register_user_duplicate_email(self):
        self.client.post(self.register_url, self.user_data, format='json')
        response = self.client.post(self.register_url, self.user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)

    def test_login_user(self):
        self.client.post(self.register_url, self.user_data, format='json')
        login_data = {'email': 'johnDoe@email.com', 'password': 'password'}
        login_url = reverse('login')
        response = self.client.post(login_url, login_data, format='json')
        print(response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'success')
        self.assertIsNotNone(User.objects.filter(email=response.data['data']['user']['email']))
        self.assertIsNotNone(User.objects.filter(email=response.data['data']['user']['userId']))
        self.assertEqual(login_data['email'], response.data['data']['user']['email'])
        user = User.objects.get(email=response.data['data']['user']['email'])
        self.assertTrue(user.check_password(login_data['password']))
        self.assertIn('accessToken', response.data['data'])

    def test_login_user_missing_fields(self):
        self.client.post(self.register_url, self.user_data, format='json')
        login_data = {'email': 'johnDoe@email.com', 'password': None}
        login_url: str = reverse('login')
        response: {} = self.client.post(login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['status'], 'Bad Request')

    def test_register_user_organisation_is_created(self):
        response: {} = self.client.post(self.register_url, self.user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        organisation: Organisation = Organisation.objects.filter(
            name__contains=response.data['data']['user']['firstName']).first()
        self.assertIsNotNone(organisation)
        self.assertTrue(organisation.name.__contains__(response.data['data']['user']['firstName']))

    def test_get_user_record_with_user_id(self):
        self.url = reverse('user-detail', kwargs={'userId': self.user.userId})
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + str(self.tokens.access_token))

        response: {} = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user = User.objects.get(email=response.data['data']['email'])
        self.assertEqual(response.data['status'], 'success')
        self.assertEqual(user.userId, response.data['data']['userId'])
        self.assertEqual(user.firstName, response.data['data']['firstName'])
        self.assertEqual(user.lastName, response.data['data']['lastName'])

    def test_user_detail_unauthenticated(self):
        self.url = reverse('user-detail', kwargs={'userId': self.user.userId})
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_user_detail_other_user(self):
        other_user =User.objects.create_user(
            firstName="John",
            lastName="Doe",
            email="john.doe@example.com",
            password="password123",
            phone="1234567890"
        )
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + str(self.tokens.access_token))
        url = reverse('user-detail', kwargs={'userId': other_user.userId})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_get_organisations_user_created(self):
        self.org1 = Organisation.objects.create( name="John's Organisation", description="Org 1")
        self.org2 = Organisation.objects.create( name="Jane's Organisation", description="Org 2")
        other_user = User.objects.create_user(
            firstName="John",
            lastName="Doe",
            email="john.doe@example.com",
            password="password123",
            phone="1234567890"
        )
        self.org1.members.add(self.user)
        self.org2.members.add(self.user)
        self.org2.members.add(other_user)
        url = reverse('user-organisations')
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + str(self.tokens.access_token))
        response = self.client.get(url)

        self.assertEqual(len(response.data['data']['organisations']), 2)

    def test_user_organisations_authenticated(self):
        self.org1 = Organisation.objects.create( name="John's Organisation", description="Org 1")
        self.org2 = Organisation.objects.create( name="Jane's Organisation", description="Org 2")

        self.org1.members.add(self.user)
        self.org2.members.add(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + str(self.tokens.access_token))
        url = reverse('user-organisations')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['data']['organisations']), 2)
        organisation_names = [org['name'] for org in response.data['data']['organisations']]
        self.assertIn("John's Organisation", organisation_names)
        self.assertIn("Jane's Organisation", organisation_names)

    def test_user_organisations_unauthenticated(self):
        url = reverse('user-organisations')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_organisation_with_id(self):
        self.client.post(self.register_url, self.user_data, format='json')
        user = User.objects.get(email=self.user_data['email'])
        org = Organisation.objects.filter(members=user).first()
        url = reverse('get-organisation', kwargs={'orgId': org.orgId})
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + str(self.tokens.access_token))
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['data']['name'], "John's Organisation")

    def test_get_single_organisation_unauthenticated(self):
        org1 = Organisation.objects.create( name="John's Organisation", description="Org 1")
        org2 = Organisation.objects.create( name="Jane's Organisation", description="Org 2")

        url = reverse('get-organisation', kwargs={'orgId': org1.orgId})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_create_organisation(self):
        url = reverse('create-organisation')
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + str(self.tokens.access_token))
        request_data = {
            "name": "New Organisation",
            "description": "A new organisation"
        }
        response = self.client.post(url, request_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['data']['name'], "New Organisation")

    def test_add_user_to_organisation(self):
        other_user = User.objects.create_user(
            firstName="John",
            lastName="Doe",
            email="john.doe@example.com",
            password="password123",
            phone="1234567890"
        )
        org1 = Organisation.objects.create( name="John's Organisation", description="Org 1")

        url = reverse('add-user-to-organisation', kwargs={'orgId': org1.orgId})
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + str(self.tokens.access_token))
        data = {
            "userId": other_user.userId
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(other_user, org1.members.all())