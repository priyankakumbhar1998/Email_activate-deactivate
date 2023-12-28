from rest_framework import permissions

class IsOwnerOrAdminOnlyOrReadOnly(permissions.BasePermission):

    def has_permission(self, request, view):
        return True
    
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return bool((request.user == obj) or request.user.is_staff)
    
class IsOwnerOrAdminOnly(permissions.BasePermission):

    def has_permission(self, request, view):
        return True
    
    def has_object_permission(self, request, view, obj):
        return bool((request.user == obj) or request.user.is_staff)
    