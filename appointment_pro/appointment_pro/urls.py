from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from auth_app.views import UserViewSet, AccountVerify, ReactivateAccount
from rest_framework_simplejwt.views import token_obtain_pair, token_refresh

router = DefaultRouter()
router.register('users', UserViewSet, basename='users')


urlpatterns = [
    path('admin/', admin.site.urls),
    path('v1/', include('appointment_app.urls')),
    path('v1/', include(router.urls)),
    path('v1/account-activate/<token>/', AccountVerify.as_view(), name="account-activate"),
    path('v1/account-reactivate/<token>/', ReactivateAccount.as_view(), name="account-reactivate"),
    path('v1/access/', token_obtain_pair, name="access-token"),
    path('v1/refresh/', token_refresh, name="refresh-token"),
   
]
