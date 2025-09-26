from django.http import HttpResponseForbidden

from accounts.models.perms import SysFieldPermission, SysPermission
from accounts.models.resources import SysResource


class PermissionChecker:
    """权限检查工具类"""

    @staticmethod
    def check_permission(user, resource_code, required_permission_type):
        """
        静态方法检查权限
        """
        return user.has_permission(resource_code, required_permission_type)

    @staticmethod
    def require_permission(resource_code, required_permission_type):
        """
        装饰器：要求用户具有指定权限
        直接在装饰器中指定resource_code和required_permission_type
        """

        def decorator(view_func):
            def wrapper(request, *args, **kwargs):
                if not request.user.is_authenticated:
                    return HttpResponseForbidden("用户未登录")

                if not request.user.has_permission(
                    resource_code, required_permission_type
                ):
                    return HttpResponseForbidden("权限不足")

                return view_func(request, *args, **kwargs)

            return wrapper

        return decorator

    @classmethod
    def require_read_permission(cls, resource_code):
        """快捷方法：要求读取权限"""
        return cls.require_permission(resource_code, SysPermission.PERM_READ)

    @classmethod
    def require_write_permission(cls, resource_code):
        """快捷方法：要求写入权限"""
        return cls.require_permission(resource_code, SysPermission.PERM_WRITE)

    @classmethod
    def require_delete_permission(cls, resource_code):
        """快捷方法：要求删除权限"""
        return cls.require_permission(resource_code, SysPermission.PERM_DELETE)

    @classmethod
    def require_manage_permission(cls, resource_code):
        """快捷方法：要求管理权限"""
        return cls.require_permission(resource_code, SysPermission.PERM_MANAGE)
