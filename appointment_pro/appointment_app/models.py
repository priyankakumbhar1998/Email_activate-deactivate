from django.db import models

class Appointment(models.Model):
    patient_name = models.CharField(max_length=30)
    patient_no = models.IntegerField()
    doctor_name = models.CharField(max_length=30)
    date = models.DateField()
