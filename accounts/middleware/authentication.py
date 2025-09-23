"""
基于 Session 的权限验证中间件
符合 Django 3.2+ 和 pylint 规范
"""

import re

from django.contrib.auth import login, logout
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.utils.translation import gettext_lazy as _

from accounts.models import (
    SysMenu,
    SysRoleColumnPermission,
    SysRoleMenuPermission,
    SysRoleResourcePermission,
    SysUser,
    SysUserRole,
)


class SessionAuthenticationMiddleware(MiddlewareMixin):
    """
    Session 认证中间件
    处理用户登录、权限验证和会话管理
    """

    # 不需要认证的白名单路径
    WHITE_LIST = [
        r"/api/auth/login/$",
        r"/api/auth/logout/$",
        r"/admin/",
        r"/static/",
        r"/media/",
        r"/api/docs/",
    ]

    # 需要权限验证的 API 路径模式
    API_PATTERN = r"^/api/.+$"

    def process_request(self, request):
        """
        处理每个请求前的认证和权限检查
        """
        # 检查是否为白名单路径
        if self._is_white_list_path(request.path):
            return None

        # 检查用户认证状态
        if not request.user.is_authenticated:
            if self._is_api_request(request.path):
                return JsonResponse(
                    {"code": 401, "message": _("用户未登录或会话已过期"), "data": None},
                    status=401,
                )
            # 对于非 API 请求，重定向到登录页
            from django.shortcuts import redirect

            return redirect("/login/")

        # 对于 API 请求，进行权限验证
        if self._is_api_request(request.path):
            if not self._check_permission(request):
                return JsonResponse(
                    {"code": 403, "message": _("权限不足"), "data": None}, status=403
                )

        # 将用户权限信息添加到请求对象中，方便视图函数使用
        request.user_permissions = self._get_user_permissions(request.user)

        return None

    def _is_white_list_path(self, path):
        """检查路径是否在白名单中"""
        for pattern in self.WHITE_LIST:
            if re.match(pattern, path):
                return True
        return False

    def _is_api_request(self, path):
        """检查是否为 API 请求"""
        return re.match(self.API_PATTERN, path) is not None

    def _check_permission(self, request):
        """
        检查用户是否有访问当前 API 的权限
        """
        # 超级用户拥有所有权限
        if getattr(request.user, "is_superuser", False):
            return True

        # 获取请求的方法和路径
        method = request.method
        path = request.path

        # 将 HTTP 方法映射为权限级别
        method_to_level = {
            "GET": SysRoleMenuPermission.PERM_LEVEL_READ,
            "POST": SysRoleMenuPermission.PERM_LEVEL_WRITE,
            "PUT": SysRoleMenuPermission.PERM_LEVEL_WRITE,
            "PATCH": SysRoleMenuPermission.PERM_LEVEL_WRITE,
            "DELETE": SysRoleMenuPermission.PERM_LEVEL_DELETE,
        }

        required_level = method_to_level.get(
            method, SysRoleMenuPermission.PERM_LEVEL_READ
        )

        # 检查菜单权限
        if self._check_menu_permission(request.user, path, required_level):
            return True

        # 检查资源权限 (API 权限)
        if self._check_resource_permission(request.user, path, method, required_level):
            return True

        return False

    def _check_menu_permission(self, user, path, required_level):
        """
        检查菜单权限
        """
        try:
            # 根据路径查找对应的菜单
            menu = SysMenu.objects.filter(menu_path=path).first()
            if not menu:
                return False

            # 获取用户的所有角色
            user_roles = SysUserRole.objects.filter(user=user).select_related("role")
            role_ids = [ur.role.role_id for ur in user_roles]

            # 检查角色是否有该菜单的足够权限
            permission = SysRoleMenuPermission.objects.filter(
                role_id__in=role_ids,
                menu=menu,
                permission_level__gte=required_level,
                is_granted=True,
            ).first()

            return permission is not None

        except Exception:  # pylint: disable=broad-except
            return False

    def _check_resource_permission(self, user, path, method, required_level):
        """
        检查资源权限 (API 权限)
        """
        try:
            # 将 API 路径转换为资源标识码
            resource_code = self._path_to_resource_code(path, method)

            # 获取用户的所有角色
            user_roles = SysUserRole.objects.filter(user=user).select_related("role")
            role_ids = [ur.role.role_id for ur in user_roles]

            # 检查角色是否有该资源的足够权限
            permission = SysRoleResourcePermission.objects.filter(
                role_id__in=role_ids,
                resource_code=resource_code,
                resource_type=SysRoleResourcePermission.RESOURCE_API,
                permission_level__gte=required_level,
            ).first()

            return permission is not None

        except Exception:  # pylint: disable=broad-except
            return False

    def _path_to_resource_code(self, path, method):
        """
        将 API 路径转换为资源标识码
        例如: /api/users/ -> api:users:get
        """
        # 清理路径
        clean_path = path.strip("/")
        # 将路径转换为资源码
        resource_code = f"api:{clean_path.replace('/', ':')}:{method.lower()}"
        return resource_code

    def _get_user_permissions(self, user):
        """
        获取用户的完整权限信息
        """
        permissions = {"menus": [], "resources": [], "columns": {}}

        if not user.is_authenticated:
            return permissions

        # 获取用户角色
        user_roles = SysUserRole.objects.filter(user=user).select_related("role")
        role_ids = [ur.role.role_id for ur in user_roles]

        if not role_ids:
            return permissions

        # 获取菜单权限
        menu_permissions = SysRoleMenuPermission.objects.filter(
            role_id__in=role_ids, is_granted=True
        ).select_related("menu")

        for perm in menu_permissions:
            permissions["menus"].append(
                {
                    "menu_id": perm.menu.menu_id,
                    "menu_name": perm.menu.menu_name,
                    "menu_path": perm.menu.menu_path,
                    "permission_level": perm.permission_level,
                }
            )

        # 获取资源权限
        resource_permissions = SysRoleResourcePermission.objects.filter(
            role_id__in=role_ids
        ).select_related("role")

        for perm in resource_permissions:
            permissions["resources"].append(
                {
                    "resource_type": perm.resource_type,
                    "resource_code": perm.resource_code,
                    "resource_name": perm.resource_name,
                    "permission_level": perm.permission_level,
                }
            )

        # 获取字段权限
        column_permissions = SysRoleColumnPermission.objects.filter(
            role_id__in=role_ids
        ).select_related("column", "column__table")

        for perm in column_permissions:
            table_name = perm.column.table.table_name
            if table_name not in permissions["columns"]:
                permissions["columns"][table_name] = {}

            permissions["columns"][table_name][perm.column.column_name] = {
                "can_read": perm.can_read,
                "can_write": perm.can_write,
                "can_export": perm.can_export,
            }

        return permissions


class AuthViewHelper:
    """
    认证视图辅助类
    提供登录、登出等功能的工具方法
    """

    @staticmethod
    def login_user(request, username, password):
        """
        用户登录
        """
        try:
            # 查找用户
            user = SysUser.objects.filter(username=username, is_active=True).first()
            if not user:
                return False, _("用户不存在或已被禁用")

            # 验证密码 (实际项目中密码应该是加密存储的)
            # 这里假设密码是明文存储，实际应该使用 check_password
            if (
                user.password != password
            ):  # 实际应该用: check_password(password, user.password)
                return False, _("密码错误")

            # 使用 Django 的登录功能建立 session
            login(request, user)

            # 更新最后登录时间
            user.save()

            return True, _("登录成功")

        except Exception as e:  # pylint: disable=broad-except
            return False, _(f"登录失败: {str(e)}")

    @staticmethod
    def logout_user(request):
        """
        用户登出
        """
        try:
            logout(request)
            return True, _("登出成功")
        except Exception as e:  # pylint: disable=broad-except
            return False, _(f"登出失败: {str(e)}")

    @staticmethod
    def get_current_user_info(request):
        """
        获取当前用户信息
        """
        if not request.user.is_authenticated:
            return None

        user = request.user
        user_info = {
            "user_id": user.user_id,
            "username": user.username,
            "user_name": user.user_name,
            "email": user.email,
            "is_superuser": user.is_superuser,
        }

        return user_info
