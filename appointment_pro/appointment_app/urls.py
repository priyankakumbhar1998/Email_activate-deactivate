from django.urls import path
from .views import AppointmentAPI, AppointmentDetailsAPI

urlpatterns = [
    path('appointment/', AppointmentAPI.as_view()),
    path('appointment/<int:pk>/', AppointmentDetailsAPI.as_view()),
]