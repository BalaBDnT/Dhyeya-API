from django.urls import path
from .views import userAuthentication

urlpatterns = [
    path('api/users/<str:action>/', userAuthentication.as_view(), name='auth_api'),
]
