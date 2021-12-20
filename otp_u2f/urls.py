from django.urls import path

from . import views

app_name = 'otp_u2f'

urlpatterns = [
    path('authenticate/', views.AuthenticateChallengeView.as_view(),
         name='authenticate'),
    path('register/', views.RegisterChallengeView.as_view(), name='register'),
]
