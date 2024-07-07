from django.urls import path

from user_manager import views
from user_manager.views import UserOrganisationsView, GetOrganisationView, CreateOrganisationView, \
    AddUserToOrganisationView

urlpatterns = [
    path('auth/register/', views.RegisterUserView.as_view(), name='register'),
    path('auth/login/', views.LoginUserView.as_view(), name='login'),
    path('api/users/<int:userId>', views.UserDetailView.as_view(), name='user-detail'),
    path('api/organisations/', UserOrganisationsView.as_view(), name='user-organisations'),
    path('api/organisations/<int:orgId>', GetOrganisationView.as_view(), name='get-organisation'),
    path('api/organisations/', CreateOrganisationView.as_view(), name='create-organisation'),
    path('api/organisations/<str:orgId>/users/', AddUserToOrganisationView.as_view(), name='add-user-to-organisation'),

]