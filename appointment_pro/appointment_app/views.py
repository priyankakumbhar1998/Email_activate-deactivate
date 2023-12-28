from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import AppointmentSerializer
from .models import Appointment
from django.shortcuts import get_object_or_404
import logging
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated

error_logger = logging.getLogger('error_logger')
success_logger = logging.getLogger('success_logger')

class AppointmentAPI(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            app = Appointment.objects.all()
            serializer = AppointmentSerializer(app, many=True)
            success_logger.info("all appointment fetched successfully!!!")
            return Response(data=serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            error_logger.error('There is an error fetching all data')
            return Response(data={'deatil' : "There is an error fetching the all Appointments"}, status=status.HTTP_400_BAD_REQUEST)
        
    def post(Self, request):
        try:
            serializer = AppointmentSerializer(data=request.data, context={'request': request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            success_logger.info(f"appointment with id {serializer.data.get('id')} created successfully!")
            return Response(data=serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            error_logger.error(f"failed to create APPointment : {serializer.errors}")
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class AppointmentDetailsAPI(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        try:
            app = get_object_or_404(Appointment, pk=pk)
            serializer = AppointmentSerializer(app)
            success_logger.info(f"Appointment details fetched : {serializer.data}")
            return Response(data=serializer.data, status=status.HTTP_200_OK)
        except Exception as e :
             error_logger.error(f"There is an error fetching the appointment details")
             return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    def put(self, request, pk=None):
        try:
            app = get_object_or_404(Appointment, pk=pk)
            serializer = AppointmentSerializer(app, data=request.data)
            if serializer.is_valid():
                instance = serializer.save()
                success_logger.info(f"Appointment updated!! : {instance}")
                return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            error_logger.error(f"Failed to update Appointment {pk} : {serializer.errors}")
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        

    def delete(self, request, pk=None):
        try:
            app = get_object_or_404(Appointment, pk=pk)
            app.delete()
            success_logger.info(f'Appointment deleted Successfully: {pk}')
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            error_logger.error(f'Failed to delete Appointment')
            return Response(data={'detail': 'Error deleting Appointment'}, status=status.HTTP_400_BAD_REQUEST)
