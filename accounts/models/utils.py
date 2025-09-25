from django.http import HttpResponseForbidden


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


class FieldPermissionManager:
    """
    字段权限管理器 - 提供字段级权限控制的工具方法
    """

    def __init__(self, user):
        self.user = user

    def get_readable_fields(self, table_name):
        """获取用户可读的字段列表"""
        return self._get_permitted_fields(table_name, SysFieldPermission.PERM_READ)

    def get_writable_fields(self, table_name):
        """获取用户可写的字段列表"""
        return self._get_permitted_fields(table_name, SysFieldPermission.PERM_WRITE)

    def get_exportable_fields(self, table_name):
        """获取用户可导出的字段列表"""
        return self._get_permitted_fields(table_name, SysFieldPermission.PERM_EXPORT)

    def _get_permitted_fields(self, table_name, permission_type):
        """获取具有指定权限的字段列表"""
        table_resource = SysResource.objects.filter(
            resource_type=SysResource.RESOURCE_TABLE,
            table_name=table_name,
            is_active=True,
        ).first()

        if not table_resource:
            return []

        permitted_fields = []
        for field_resource in table_resource.get_table_fields():
            if SysFieldPermission.check_field_permission(
                self.user, table_name, field_resource.field_name, permission_type
            ):
                permitted_fields.append(field_resource.field_name)

        return permitted_fields

    def filter_queryset_fields(self, queryset, table_name):
        """
        过滤查询集的字段，只返回有读取权限的字段
        """
        readable_fields = self.get_readable_fields(table_name)
        if not readable_fields:
            return queryset.none()

        # 只选择有权限的字段
        fields_to_select = [
            field for field in readable_fields if hasattr(queryset.model, field)
        ]
        return queryset.only(*fields_to_select)

    def get_field_permission_conditions(self, table_name, field_name, permission_type):
        """
        获取字段权限的条件限制
        """
        table_resource = SysResource.objects.filter(
            resource_type=SysResource.RESOURCE_TABLE,
            table_name=table_name,
            is_active=True,
        ).first()

        if not table_resource:
            return None

        field_resource = table_resource.get_field_resource(field_name)
        if not field_resource:
            return None

        conditions = []
        for user_role in self.user.get_all_roles():
            perms = SysFieldPermission.objects.filter(
                role=user_role,
                field_resource=field_resource,
                permission_type=permission_type,
                is_active=True,
                is_granted=True,
            )
            for perm in perms:
                condition = perm.get_condition_expression()
                if condition:
                    conditions.append(condition)

        return conditions

    def apply_field_permissions(self, queryset, table_name, operation="read"):
        """
        应用字段权限到查询集
        """
        if operation == "read":
            # 过滤字段
            queryset = self.filter_queryset_fields(queryset, table_name)
        elif operation == "write":
            # 对于写入操作，可以添加额外的验证
            pass

        return queryset
