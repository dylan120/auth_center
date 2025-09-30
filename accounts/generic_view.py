# permissions/views.py 或 utils/views.py

from typing import Any, Dict, List

from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import BasePermission
from rest_framework.response import Response


class PermissionGenericView(GenericAPIView):
    """
    支持 method-level 权限控制的通用视图基类
    子类通过 `permission_map` 指定每个 HTTP 方法所需的权限
    """

    # {method: [permission_codename]}
    permission_map: Dict[str, List[str]] = {}

    def get_required_permissions(self, method: str) -> List[str]:
        """
        获取当前请求方法所需的权限列表
        可被子类重写以动态生成权限
        """
        return self.permission_map.get(method, [])

    def check_permissions(self, request):
        """
        重写父类方法，按请求方法检查权限
        """
        # 获取当前请求方法
        method = request.method.upper()

        # 获取该方法所需权限
        required_permissions = self.get_required_permissions(method)

        # 如果没有权限要求，跳过检查
        if not required_permissions:
            return

        # 检查用户是否拥有所有所需权限
        user = request.user
        if not user.is_authenticated:
            self.permission_denied(request, message="Authentication required.")

        # 检查每个权限
        for perm in required_permissions:
            if not user.has_perm(perm):
                self.permission_denied(request, message=f"Permission denied: {perm}")

    def get(self, request, *args, **kwargs):
        return Response(
            {"detail": "GET method not implemented"},
            status=status.HTTP_501_NOT_IMPLEMENTED,
        )

    def post(self, request, *args, **kwargs):
        return Response(
            {"detail": "POST method not implemented"},
            status=status.HTTP_501_NOT_IMPLEMENTED,
        )

    def put(self, request, *args, **kwargs):
        return Response(
            {"detail": "PUT method not implemented"},
            status=status.HTTP_501_NOT_IMPLEMENTED,
        )

    def patch(self, request, *args, **kwargs):
        return Response(
            {"detail": "PATCH method not implemented"},
            status=status.HTTP_501_NOT_IMPLEMENTED,
        )

    def delete(self, request, *args, **kwargs):
        return Response(
            {"detail": "DELETE method not implemented"},
            status=status.HTTP_501_NOT_IMPLEMENTED,
        )

    def head(self, request, *args, **kwargs):
        return self.http_method_not_allowed(request, *args, **kwargs)

    def options(self, request, *args, **kwargs):
        return Response(status=status.HTTP_200_OK)
