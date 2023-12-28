# Generated by Django 5.0 on 2023-12-26 17:58

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Appointment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('patient_name', models.CharField(max_length=30)),
                ('patient_no', models.IntegerField()),
                ('doctor_name', models.CharField(max_length=30)),
                ('date', models.DateField()),
            ],
        ),
    ]