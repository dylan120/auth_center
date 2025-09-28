"""
认证相关的视图函数
"""

import json

from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .middleware.authentication import AuthViewHelper


@method_decorator(csrf_exempt, name="dispatch")
class LoginView(View):
    """
    用户登录视图
    """

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        """获取登录数据"""
        try:
            data = json.loads(request.body) if request.body else {}
            username = data.get("username", "").strip()
            password = data.get("password", "").strip()
        except json.JSONDecodeError:
            return JsonResponse(
                {"code": 400, "message": _("请求数据格式错误"), "data": None},
                status=400,
            )

        # 验证输入
        if not username or not password:
            return JsonResponse(
                {"code": 400, "message": _("用户名和密码不能为空"), "data": None},
                status=400,
            )

        # 执行登录
        success, message = AuthViewHelper.login_user(request, username, password)

        if success:
            user_info = AuthViewHelper.get_current_user_info(request)
            return JsonResponse(
                {
                    "code": 200,
                    "message": message,
                    "data": {
                        "user": user_info,
                        "session_id": request.session.session_key,
                    },
                }
            )
        else:
            return JsonResponse(
                {"code": 401, "message": message, "data": None}, status=401
            )


@require_http_methods(["POST"])
@csrf_exempt
def logout_view(request):
    """
    用户登出视图
    """
    success, message = AuthViewHelper.logout_user(request)

    if success:
        return JsonResponse({"code": 200, "message": message, "data": None})
    else:
        return JsonResponse({"code": 500, "message": message, "data": None}, status=500)


@require_http_methods(["GET"])
def current_user_view(request):
    """
    获取当前用户信息视图
    """
    user_info = AuthViewHelper.get_current_user_info(request)

    if user_info:
        return JsonResponse(
            {
                "code": 200,
                "message": _("获取用户信息成功"),
                "data": {
                    "user": user_info,
                    "permissions": getattr(request, "user_permissions", {}),
                },
            }
        )
    else:
        return JsonResponse(
            {"code": 401, "message": _("用户未登录"), "data": None}, status=401
        )
