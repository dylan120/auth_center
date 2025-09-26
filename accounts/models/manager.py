from accounts.models.perms import SysPermission
from accounts.models.resources import (
    SysApiResource,
    SysFieldResource,
    SysMenuResource,
    SysModuleResource,
    SysResource,
    SysTableResource,
)
from accounts.models.user import SysUser


class ResourceManager:
    """
    资源管理器 - 提供统一的资源操作接口
    """

    @classmethod
    def get_resource_model(cls, resource_type):
        """根据资源类型获取对应的模型类"""
        resource_models = {
            SysResource.RESOURCE_MENU: SysMenuResource,
            SysResource.RESOURCE_API: SysApiResource,
            SysResource.RESOURCE_TABLE: SysTableResource,
            SysResource.RESOURCE_FIELD: SysFieldResource,
            SysResource.RESOURCE_MODULE: SysModuleResource,
        }
        return resource_models.get(resource_type)

    @classmethod
    def create_resource(cls, resource_type, **kwargs):
        """创建资源"""
        model_class = cls.get_resource_model(resource_type)
        if not model_class:
            raise ValueError(f"不支持的资源类型: {resource_type}")

        return model_class.objects.create(**kwargs)

    @classmethod
    def get_resource(cls, resource_id, resource_type=None):
        """获取资源"""
        if resource_type:
            model_class = cls.get_resource_model(resource_type)
            return model_class.objects.get(resource_id=resource_id)
        else:
            # 如果没有指定类型，尝试在所有资源表中查找
            for resource_type in SysResource.RESOURCE_TYPE_CHOICES:
                model_class = cls.get_resource_model(resource_type[0])
                try:
                    return model_class.objects.get(resource_id=resource_id)
                except model_class.DoesNotExist:
                    continue
            raise SysResource.DoesNotExist(f"资源不存在: {resource_id}")

    @classmethod
    def get_resources_by_company(cls, company, resource_type=None):
        """获取公司下的所有资源"""
        resources = []

        if resource_type:
            model_class = cls.get_resource_model(resource_type)
            resources = list(
                model_class.objects.filter(company=company, is_active=True)
            )
        else:
            # 获取所有类型的资源
            for resource_type in SysResource.RESOURCE_TYPE_CHOICES:
                model_class = cls.get_resource_model(resource_type[0])
                resources.extend(
                    list(model_class.objects.filter(company=company, is_active=True))
                )

        return resources


class FieldPermissionManager:
    """字段权限管理工具类"""

    @staticmethod
    def create_field_permissions(table_resource: SysTableResource):
        """为表的所有字段创建默认权限"""
        for field_resource in table_resource.get_fields():
            # 创建读取权限
            SysPermission.objects.get_or_create(
                resource=field_resource,
                permission_type=SysPermission.PERM_READ,
                defaults={
                    "permission_code": f"{field_resource.resource_code}.read",
                    "permission_name": f"读取{field_resource.field_label}",
                    "description": f"读取{field_resource.table_resource.table_name}.{field_resource.field_name}字段",
                },
            )

            # 创建写入权限
            SysPermission.objects.get_or_create(
                resource=field_resource,
                permission_type=SysPermission.PERM_WRITE,
                defaults={
                    "permission_code": f"{field_resource.resource_code}.write",
                    "permission_name": f"编辑{field_resource.field_label}",
                    "description": f"编辑{field_resource.table_resource.table_name}.{field_resource.field_name}字段",
                },
            )

    @staticmethod
    def check_field_permission(user, table_name, field_name, permission_type):
        """检查字段权限（使用统一权限系统）"""
        # 查找字段资源
        field_resource = SysFieldResource.objects.filter(
            table_resource__table_name=table_name, field_name=field_name, is_active=True
        ).first()

        if not field_resource:
            return False

        # 使用统一权限检查
        return user.has_permission(field_resource.resource_code, permission_type)

    @staticmethod
    def get_user_field_permissions(user: SysUser, table_name):
        """获取用户对表字段的权限"""
        permissions = {}
        field_resources = SysFieldResource.objects.filter(
            table_resource__table_name=table_name, is_active=True
        )

        for field_resource in field_resources:
            permissions[field_resource.field_name] = {
                "can_read": user.has_permission(
                    field_resource.resource_code, SysPermission.PERM_READ
                ),
                "can_write": user.has_permission(
                    field_resource.resource_code, SysPermission.PERM_WRITE
                ),
                "field_label": field_resource.field_label,
            }

        return permissions

    @classmethod
    def get_readable_fields(cls, user, table_name, company_id=None):
        """
        获取用户可读取的字段列表
        """
        return cls._get_permitted_fields(
            user, table_name, SysPermission.PERM_READ, company_id
        )

    @classmethod
    def get_writable_fields(cls, user, table_name, company_id=None):
        """
        获取用户可写入的字段列表
        """
        return cls._get_permitted_fields(
            user, table_name, SysPermission.PERM_WRITE, company_id
        )

    @classmethod
    def _get_permitted_fields(cls, user, table_name, permission_type, company_id=None):
        """
        获取用户有指定权限的字段列表
        """
        # 获取表资源
        table_resource = cls._get_table_resource(table_name, company_id)
        if not table_resource:
            return []

        permitted_fields = []

        # 检查每个字段的权限
        for field_resource in table_resource.get_fields():
            field_perm_code = field_resource.resource_code

            # 检查用户是否有该字段的指定权限
            if user.has_permission(field_perm_code, permission_type):
                permitted_fields.append(
                    {
                        "field_name": field_resource.field_name,
                        "field_label": field_resource.field_label,
                        "field_type": field_resource.field_type,
                        "is_sensitive": field_resource.is_sensitive,
                        "field_resource": field_resource,
                    }
                )

        return permitted_fields

    @classmethod
    def filter_queryset_fields(cls, queryset, user, table_name, company_id=None):
        """
        根据字段权限过滤查询集，只返回有权限的字段
        """
        readable_fields = cls.get_readable_fields(user, table_name, company_id)
        if not readable_fields:
            return queryset.none()

        # 构建只包含可读字段的values列表
        field_names = [field["field_name"] for field in readable_fields]

        # 确保包含主键字段（如果存在）
        model = queryset.model
        pk_name = model._meta.pk.name
        if pk_name not in field_names:
            field_names.insert(0, pk_name)

        return queryset.values(*field_names)

    @classmethod
    def get_field_permission_conditions(
        cls, user, table_name, operation_type, company_id=None
    ):
        """
        获取字段权限的条件限制（用于序列化器或表单验证）
        """
        conditions = {}

        if operation_type == SysPermission.PERM_READ:
            permitted_fields = cls.get_readable_fields(user, table_name, company_id)
        elif operation_type == SysPermission.PERM_WRITE:
            permitted_fields = cls.get_writable_fields(user, table_name, company_id)
        else:
            return conditions

        for field_info in permitted_fields:
            field_name = field_info["field_name"]
            field_resource = field_info["field_resource"]

            # 获取字段的额外权限条件
            field_conditions = cls._get_field_extra_conditions(
                user, field_resource, operation_type
            )
            if field_conditions:
                conditions[field_name] = field_conditions

        return conditions

    @classmethod
    def apply_field_permissions(
        cls, serializer_instance, user, table_name, operation_type, company_id=None
    ):
        """
        在序列化器上应用字段权限
        """
        if operation_type == SysPermission.PERM_READ:
            # 移除无读取权限的字段
            readable_fields = cls.get_readable_fields(user, table_name, company_id)
            readable_field_names = {field["field_name"] for field in readable_fields}

            for field_name in list(serializer_instance.fields.keys()):
                if field_name not in readable_field_names:
                    serializer_instance.fields.pop(field_name)

        elif operation_type == SysPermission.PERM_WRITE:
            # 设置无写入权限的字段为只读
            writable_fields = cls.get_writable_fields(user, table_name, company_id)
            writable_field_names = {field["field_name"] for field in writable_fields}

            for field_name, field in serializer_instance.fields.items():
                if field_name not in writable_field_names:
                    field.read_only = True

        return serializer_instance

    @classmethod
    def get_field_permission_summary(cls, user, table_name, company_id=None):
        """
        获取字段权限摘要信息
        """
        table_resource = cls._get_table_resource(table_name, company_id)
        if not table_resource:
            return {}

        summary = {
            "table_name": table_name,
            "total_fields": 0,
            "readable_fields": 0,
            "writable_fields": 0,
            "sensitive_fields": 0,
            "field_details": [],
        }

        for field_resource in table_resource.get_fields():
            summary["total_fields"] += 1

            if field_resource.is_sensitive:
                summary["sensitive_fields"] += 1

            can_read = user.has_permission(
                field_resource.resource_code, SysPermission.PERM_READ
            )
            can_write = user.has_permission(
                field_resource.resource_code, SysPermission.PERM_WRITE
            )

            if can_read:
                summary["readable_fields"] += 1
            if can_write:
                summary["writable_fields"] += 1

            summary["field_details"].append(
                {
                    "field_name": field_resource.field_name,
                    "field_label": field_resource.field_label,
                    "field_type": field_resource.field_type,
                    "is_sensitive": field_resource.is_sensitive,
                    "can_read": can_read,
                    "can_write": can_write,
                }
            )

        return summary

    @classmethod
    def validate_field_access(
        cls, user, table_name, field_name, operation_type, company_id=None
    ):
        """
        验证用户对特定字段的访问权限
        """
        if operation_type == SysPermission.PERM_READ:
            permitted_fields = cls.get_readable_fields(user, table_name, company_id)
        elif operation_type == SysPermission.PERM_WRITE:
            permitted_fields = cls.get_writable_fields(user, table_name, company_id)
        else:
            return False

        permitted_field_names = {field["field_name"] for field in permitted_fields}
        return field_name in permitted_field_names

    # 私有辅助方法
    @classmethod
    def _get_table_resource(cls, table_name, company_id=None):
        """获取表资源对象"""
        try:
            qs = SysTableResource.objects.filter(table_name=table_name, is_active=True)
            if company_id:
                qs = qs.filter(company_id=company_id)
            return qs.first()
        except SysTableResource.DoesNotExist:
            return None

    @classmethod
    def _get_field_extra_conditions(cls, user, field_resource, operation_type):
        """
        获取字段的额外权限条件（如值范围限制等）
        """
        conditions = {}

        # 查找字段的权限配置
        try:
            permission = SysPermission.objects.get(
                resource=field_resource,
                permission_type=SysPermission.PERM_MANAGE,  # 管理权限包含配置信息
                is_active=True,
            )

            # 从权限描述或扩展字段中解析条件
            if permission.description and "条件:" in permission.description:
                # 解析描述中的条件（示例）
                conditions.update(
                    cls._parse_conditions_from_description(permission.description)
                )

            # 如果有扩展配置字段（如field_config），可以在这里解析
            if hasattr(permission, "field_config") and permission.field_config:
                conditions.update(permission.field_config)

        except SysPermission.DoesNotExist:
            pass

        return conditions

    @classmethod
    def _parse_conditions_from_description(cls, description):
        """
        从权限描述中解析条件（示例实现）
        """
        conditions = {}

        # 示例：解析 "条件: 值范围[0-100], 可选值[A,B,C]"
        if "值范围[" in description and "]" in description:
            import re

            range_match = re.search(r"值范围\[([^\]]+)\]", description)
            if range_match:
                range_str = range_match.group(1)
                if "-" in range_str:
                    min_val, max_val = range_str.split("-")
                    conditions["value_range"] = {
                        "min": float(min_val) if "." in min_val else int(min_val),
                        "max": float(max_val) if "." in max_val else int(max_val),
                    }

        # 解析可选值
        if "可选值[" in description and "]" in description:
            import re

            options_match = re.search(r"可选值\[([^\]]+)\]", description)
            if options_match:
                options_str = options_match.group(1)
                conditions["allowed_values"] = [
                    opt.strip() for opt in options_str.split(",")
                ]

        return conditions

    @classmethod
    def create_field_permission_batch(cls, table_resource, permission_type, role):
        """
        批量创建字段权限
        """
        permissions_created = []

        for field_resource in table_resource.get_fields():
            permission, created = SysPermission.objects.get_or_create(
                resource=field_resource,
                permission_type=permission_type,
                defaults={
                    "permission_code": f"{field_resource.resource_code}.{permission_type}",
                    "permission_name": f"{field_resource.field_label}{cls._get_perm_type_display(permission_type)}",
                    "description": f"{table_resource.table_name}.{field_resource.field_name}字段{cls._get_perm_type_display(permission_type)}权限",
                },
            )

            if created:
                permissions_created.append(permission)

        return permissions_created

    @classmethod
    def _get_perm_type_display(cls, permission_type):
        """获取权限类型显示名称"""
        perm_displays = {
            SysPermission.PERM_READ: "读取",
            SysPermission.PERM_WRITE: "编辑",
            SysPermission.PERM_DELETE: "删除",
            SysPermission.PERM_EXPORT: "导出",
        }
        return perm_displays.get(permission_type, "访问")
