from .serializers import UserSerializer
from rest_framework.response import Response
import logging
from rest_framework import viewsets, status, views, decorators
from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken
from appointment_pro.utils import send_email
import jwt
from django.conf import settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from .permissions import IsOwnerOrAdminOnlyOrReadOnly, IsOwnerOrAdminOnly
from rest_framework.exceptions import PermissionDenied, NotAuthenticated

error_logger = logging.getLogger('error_logger')
success_logger = logging.getLogger('success_logger')

User = get_user_model()


class UserViewSet(viewsets.GenericViewSet):
    serializer_class = UserSerializer
    queryset = User.objects.all()
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsOwnerOrAdminOnlyOrReadOnly]

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            success_logger.info(f'user created with username {serializer.data.get("username")}')
            token = RefreshToken.for_user(user=user).access_token
            current_site = get_current_site(request=request).domain
            relativeLink = reverse('account-activate', args=(str(token),))
            abs_url = f'http://{current_site}{relativeLink}'
            subject = "Account Activation Link"
            message = "Hello %s,\n\t Please click in the link below to activate your account.\n%s"%(user.username, abs_url)
            send_email(subject=subject, body=message, recipient_list=[user.email,])
            return Response(data=serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            error_logger.error(f'error creating user {serializer.errors}')
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    def list(self, request, *args, **kwargs):
        try:
            users = self.get_queryset()
            serializer = self.get_serializer(users, many=True)
            success_logger.info("users fetched successfully")
            return Response(data=serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            error_logger.error("error fetching users")
            return Response(data={'detail': 'Error fetching users'}, status=status.HTTP_400_BAD_REQUEST)
        
    def update(self, request, *args, **kwags):
        try:
            obj= self.get_object()
            serializer = self.get_serializer(data=request.data, instance = obj)
            serializer = serializer.is_valid(raise_exception=True)
            serializer.save()
            success_logger.info(f'user{serializer.data.get("username")} is updated')
            return Response(data=serializer.data, status=status.HTTP_205_RESET_CONTENT)
        except PermissionDenied as e :
            error_logger.error('PermssionDenied')
            return Response(data={'deatil': 'You do not have permission to access the resource'}, status=status.HTTP_400_BAD_REQUEST)
        except NotAuthenticated as e:
            error_logger.error("Authentication credentials were not provided.")
            return Response(data={'detail': "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            print(e)
            error_logger.error("error in updating users")
            return Response(data={'detail': 'Error updating users'}, status=status.HTTP_400_BAD_REQUEST)
        
    def partial_update(self, request, *args, **kwargs):
        try:
            obj = self.get_object()
            serializer = self.get_serializer(data=request.data, instance=obj, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            success_logger.info(f'User {serializer.data.get("username")} is updated ')
            return Response(data=serializer.data, status=status.HTTP_205_RESET_CONTENT)
        except PermissionDenied as e:
            error_logger.error("PermissionDenied")
            return Response(data={'detail': 'You do not have permission to access the resource'}, status=status.HTTP_403_FORBIDDEN)
        except NotAuthenticated as e:
            error_logger.error("Authentication credentials were not provided.")
            return Response(data={'detail': "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            print(e)
            error_logger.error("error in partially updating users")
            return Response(data={'detail': 'Error in partially updating users'}, status=status.HTTP_400_BAD_REQUEST)
        
    def delete(self, request, *args, **kwargs):
        try:
            obj = self.get_object()
            uid = obj.id
            obj.delete()
            success_logger.info(f'User with {uid} is deleted ')
            return Response(data=None, status=status.HTTP_205_RESET_CONTENT)
        except PermissionDenied as e:
            error_logger.error("PermissionDenied")
            return Response(data={'detail': 'You do not have permission to access the resource'}, status=status.HTTP_403_FORBIDDEN)
        except NotAuthenticated as e:
            error_logger.error("Authentication credentials were not provided.")
            return Response(data={'detail': "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            error_logger.error("error in deleting users")
            return Response(data={'detail': 'Not Found'}, status=status.HTTP_404_NOT_FOUND)

    @decorators.action(methods=['GET'], detail=True, permission_classes=[IsOwnerOrAdminOnly])
    def deactivate(self, request, *args, **kwargs):
        try:
            obj = self.get_object()
            obj.is_active = False
            obj.save()
            token = RefreshToken.for_user(user=obj).access_token
            current_site = get_current_site(request=request).domain
            relativeLink = reverse('account-reactivate', args=(str(token),))
            abs_url = f'http://{current_site}{relativeLink}'
            subject = "Account Deactivation"
            message = "Hello %s,\n\t Please click in the link below to activate your account again.\n%s"%(obj.username, abs_url)
            send_email(subject=subject, body=message, recipient_list=[obj.email,])
            success_logger.info(f"user {obj.username} is deactivated successfully")
            return Response(data={'detail': 'Account deactivated successfully'}, status=status.HTTP_200_OK)
        except PermissionDenied as e:
            error_logger.error("PermissionDenied")
            return Response(data={'detail': 'You do not have permission to access the resource'}, status=status.HTTP_403_FORBIDDEN)
        except NotAuthenticated as e:
            error_logger.error("Authentication credentials were not provided.")
            return Response(data={'detail': "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            error_logger.error("error in deactivate the users")
            return Response(data={'detail': 'Not Found'}, status=status.HTTP_404_NOT_FOUND)


class ReactivateAccount(views.APIView):

    def get(self, request, token=None): 
        try:
            payload = jwt.decode(token, settings.SECRET_KEY,algorithms=['HS256'])
            user = User.objects.get(pk=payload.get('user_id'))
            user.is_active = True
            user.save()
            return Response(data={'detail': 'Account reactivated successfully'}, status=status.HTTP_200_OK)
        except jwt.DecodeError:
            return Response(data={'detail': 'Token in expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.ExpiredSignatureError:
            return Response(data={'detail': 'Link in expired'}, status=status.HTTP_400_BAD_REQUEST)

class AccountVerify(views.APIView):

    def get(self, request, token=None):
        try:
            payload = jwt.decode(token, settings.SECRET_KEY,algorithms=['HS256'])
            user = User.objects.get(pk=payload.get('user_id'))
            user.is_active = True
            user.save()
            return Response(data={'detail': 'Account activated successfully'}, status=status.HTTP_200_OK)
        except jwt.DecodeError:
            return Response(data={'detail': 'Token in expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.ExpiredSignatureError:
            return Response(data={'detail': 'Link in expired'}, status=status.HTTP_400_BAD_REQUEST)

        


