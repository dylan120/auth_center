# View资源自动注册装饰器
class ViewResourceRegistry:
    """View资源自动注册器"""

    @staticmethod
    def register_view_resource(
        resource_code,
        resource_name,
        resource_type=SysResource.RESOURCE_API,
        path="",
        method="",
        description="",
        update_existing=True,
    ):
        """
        装饰器：自动注册View到SysResource
        """

        def decorator(view_func):
            # 获取View的模块和函数信息
            module_name = view_func.__module__
            view_name = view_func.__name__

            # 构建默认描述
            default_description = f"{resource_name} - {module_name}.{view_name}"
            final_description = description or default_description

            # 尝试获取或创建资源
            try:
                resource, created = SysResource.objects.get_or_create(
                    resource_code=resource_code,
                    defaults={
                        "resource_name": resource_name,
                        "resource_type": resource_type,
                        "path": path or f"/api/{resource_code.replace('_', '/')}",
                        "method": method or "GET,POST",
                        "description": final_description,
                        "is_active": True,
                    },
                )

                if not created and update_existing:
                    # 更新已存在的资源
                    resource.resource_name = resource_name
                    resource.resource_type = resource_type
                    resource.path = path or resource.path
                    resource.method = method or resource.method
                    resource.description = final_description
                    resource.save()

            except Exception as e:
                # 在开发阶段打印错误，生产环境可以记录日志
                print(f"注册View资源失败 {resource_code}: {e}")

            # 为View函数添加资源标识属性
            view_func._resource_code = resource_code
            view_func._resource_name = resource_name

            return view_func

        return decorator

    @classmethod
    def register_api_view(
        cls, resource_code, resource_name, path="", methods=None, description=""
    ):
        """快捷方法：注册API View"""
        method_str = ",".join(methods) if methods else "GET,POST"
        return cls.register_view_resource(
            resource_code=resource_code,
            resource_name=resource_name,
            resource_type=SysResource.RESOURCE_API,
            path=path,
            method=method_str,
            description=description,
        )

    @classmethod
    def register_menu_view(
        cls,
        resource_code,
        resource_name,
        path="",
        icon="",
        component="",
        description="",
    ):
        """快捷方法：注册菜单View"""
        return cls.register_view_resource(
            resource_code=resource_code,
            resource_name=resource_name,
            resource_type=SysResource.RESOURCE_MENU,
            path=path,
            icon=icon,
            component=component,
            description=description,
        )

    @classmethod
    def register_module_view(cls, resource_code, resource_name, description=""):
        """快捷方法：注册模块View"""
        return cls.register_view_resource(
            resource_code=resource_code,
            resource_name=resource_name,
            resource_type=SysResource.RESOURCE_MODULE,
            description=description,
        )

    @staticmethod
    def scan_and_register_views(app_name):
        """
        扫描指定应用的所有View并自动注册
        """
        try:
            from importlib import import_module
            from inspect import getmembers, isfunction

            from django.apps import apps

            app_config = apps.get_app_config(app_name)
            views_module = import_module(f"{app_config.name}.views")

            registered_count = 0
            for name, obj in getmembers(views_module):
                if isfunction(obj) and hasattr(obj, "_resource_code"):
                    # 已经通过装饰器注册的View
                    registered_count += 1
                elif hasattr(obj, "as_view") and hasattr(obj, "resource_meta"):
                    # 类View的注册（需要额外处理）
                    cls._register_class_view(obj)
                    registered_count += 1

            print(f"扫描完成，注册了 {registered_count} 个View资源")

        except Exception as e:
            print(f"扫描View资源失败: {e}")


# 类View资源注册装饰器
def register_class_view(
    resource_code, resource_name, resource_type=SysResource.RESOURCE_API, description=""
):
    """
    类View资源注册装饰器
    """

    def decorator(view_class):
        # 为类添加资源元数据
        view_class.resource_meta = {
            "resource_code": resource_code,
            "resource_name": resource_name,
            "resource_type": resource_type,
            "description": description,
        }

        # 重写as_view方法，在注册时创建资源
        original_as_view = view_class.as_view

        @classmethod
        def as_view_with_registry(cls, **initkwargs):
            # 注册资源
            ViewResourceRegistry._register_class_view(cls)
            return original_as_view(**initkwargs)

        view_class.as_view = as_view_with_registry
        return view_class

    return decorator


# 扩展ViewResourceRegistry以支持类View注册
def _register_class_view(self, view_class):
    """注册类View资源"""
    if not hasattr(view_class, "resource_meta"):
        return

    meta = view_class.resource_meta
    try:
        resource, created = SysResource.objects.get_or_create(
            resource_code=meta["resource_code"],
            defaults={
                "resource_name": meta["resource_name"],
                "resource_type": meta["resource_type"],
                "description": meta["description"],
                "is_active": True,
            },
        )

        if not created:
            resource.resource_name = meta["resource_name"]
            resource.resource_type = meta["resource_type"]
            resource.description = meta["description"]
            resource.save()

    except Exception as e:
        print(f"注册类View资源失败 {meta['resource_code']}: {e}")


ViewResourceRegistry._register_class_view = _register_class_view


# 使用示例
def example_usage():
    """使用示例"""

    # 方式1：函数视图注册
    from django.http import JsonResponse

    @ViewResourceRegistry.register_api_view(
        resource_code="user_list",
        resource_name="用户列表API",
        path="/api/users/",
        methods=["GET"],
        description="获取用户列表数据",
    )
    @PermissionChecker.require_read_permission("user_management")
    def user_list_view(request):
        return JsonResponse({"data": "用户列表"})

    # 方式2：菜单视图注册
    @ViewResourceRegistry.register_menu_view(
        resource_code="user_management_page",
        resource_name="用户管理页面",
        path="/admin/users/",
        icon="user",
        component="UserManagement",
        description="用户管理主页面",
    )
    @PermissionChecker.require_read_permission("user_management")
    def user_management_view(request):
        return JsonResponse({"page": "用户管理"})

    # 方式3：模块视图注册
    @ViewResourceRegistry.register_module_view(
        resource_code="user_module",
        resource_name="用户管理模块",
        description="用户相关的所有功能模块",
    )
    def user_module_placeholder():
        """模块占位函数"""
        pass

    # 方式4：类视图注册
    from django.utils.decorators import method_decorator
    from django.views import View

    @register_class_view(
        resource_code="user_detail_api",
        resource_name="用户详情API",
        resource_type=SysResource.RESOURCE_API,
        description="用户详情的增删改查操作",
    )
    class UserDetailView(View):
        @method_decorator(PermissionChecker.require_read_permission("user_management"))
        def get(self, request, user_id):
            return JsonResponse({"user_id": user_id})

        @method_decorator(PermissionChecker.require_write_permission("user_management"))
        def post(self, request, user_id):
            return JsonResponse({"status": "updated"})

        @method_decorator(
            PermissionChecker.require_delete_permission("user_management")
        )
        def delete(self, request, user_id):
            return JsonResponse({"status": "deleted"})

    # 方式5：REST Framework视图注册（如果使用DRF）
    try:
        from rest_framework.response import Response
        from rest_framework.views import APIView

        @register_class_view(
            resource_code="user_profile_api",
            resource_name="用户档案API",
            description="用户档案信息的REST API",
        )
        class UserProfileAPIView(APIView):
            @method_decorator(
                PermissionChecker.require_read_permission("user_management")
            )
            def get(self, request):
                return Response({"profile": "用户档案"})

    except ImportError:
        pass


# 管理命令：扫描并注册所有View资源
import os

import django
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    """Django管理命令：扫描并注册View资源"""

    help = "扫描并注册所有View资源到权限系统"

    def add_arguments(self, parser):
        parser.add_argument(
            "--app", type=str, help="指定要扫描的应用名称，不指定则扫描所有应用"
        )

    def handle(self, *args, **options):
        app_name = options.get("app")

        if app_name:
            # 扫描指定应用
            ViewResourceRegistry.scan_and_register_views(app_name)
            self.stdout.write(self.style.SUCCESS(f"成功扫描应用 {app_name} 的View资源"))
        else:
            # 扫描所有已安装的应用
            from django.apps import apps

            for app_config in apps.get_app_configs():
                if not app_config.name.startswith("django."):
                    try:
                        ViewResourceRegistry.scan_and_register_views(app_config.name)
                        self.stdout.write(
                            self.style.SUCCESS(f"成功扫描应用 {app_config.name}")
                        )
                    except Exception as e:
                        self.stdout.write(
                            self.style.ERROR(f"扫描应用 {app_config.name} 失败: {e}")
                        )


# 信号：应用启动时自动扫描
from django.apps import AppConfig


class PermissionConfig(AppConfig):
    name = "your_permission_app_name"

    def ready(self):
        """应用启动时自动扫描View资源"""
        if os.environ.get("RUN_MAIN") or not os.environ.get("DJANGO_AUTO_SCAN_VIEWS"):
            # 避免在开发服务器中重复扫描
            return

        try:
            from django.conf import settings

            if getattr(settings, "AUTO_SCAN_VIEW_RESOURCES", False):
                ViewResourceRegistry.scan_and_register_views(self.name)
        except Exception as e:
            print(f"自动扫描View资源失败: {e}")
