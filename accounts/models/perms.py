from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _

from accounts.models import BaseModel


class SysRolePermissionSet(BaseModel):
    """
    角色与权限集的关联关系
    """

    role = models.ForeignKey(
        "SysRole", on_delete=models.CASCADE, verbose_name=_("角色")
    )
    permission_set = models.ForeignKey(
        "SysPermissionSet", on_delete=models.CASCADE, verbose_name=_("权限集")
    )
    assigned_by = models.ForeignKey(
        "SysUser", on_delete=models.SET_NULL, null=True, verbose_name=_("分配人")
    )

    class Meta:
        db_table = "sys_role_permission_set"
        verbose_name = _("角色权限集关联")
        verbose_name_plural = _("角色权限集关联")
        unique_together = ("role", "permission_set")

    def __str__(self):
        return f"{self.role.role_name} - {self.permission_set.set_name}"

    def clean(self):
        """验证角色和权限集属于同一公司"""

        role_company = getattr(self.role, "company", None)
        permset_company = getattr(self.permission_set, "company", None)

        # 权限集属于某个公司（非平台级）
        if permset_company is not None:
            # 则角色必须也属于该公司（不能是平台级角色）
            if role_company is None:
                raise ValidationError(_("平台级角色不能绑定公司专属权限集"))
            if role_company != permset_company:
                raise ValidationError(_("角色和权限集必须属于同一公司"))

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)


class SysPermissionSet(BaseModel):
    """
    权限集 - 核心改进：将权限打包成集合，便于复用和管理
    类似于Linux中的用户组概念，一个角色可以关联多个权限集
    """

    # 权限集类型
    SET_TYPE_SYSTEM = 1  # 系统内置权限集
    SET_TYPE_CUSTOM = 2  # 用户自定义权限集

    SET_TYPE_CHOICES = (
        (SET_TYPE_SYSTEM, _("系统内置")),
        (SET_TYPE_CUSTOM, _("自定义")),
    )

    set_id = models.AutoField(primary_key=True, verbose_name=_("权限集ID"))

    # 权限集所属公司（Null表示全局权限集）
    company = models.ForeignKey(
        "SysCompany",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="permission_sets",
        verbose_name=_("所属公司"),
    )
    set_name = models.CharField(
        max_length=100, unique=True, verbose_name=_("权限集名称")
    )
    set_code = models.CharField(
        max_length=50, unique=True, verbose_name=_("权限集编码")
    )
    set_type = models.IntegerField(
        choices=SET_TYPE_CHOICES, default=SET_TYPE_CUSTOM, verbose_name=_("权限集类型")
    )
    description = models.TextField(blank=True, verbose_name=_("权限集描述"))
    # is_inheritable = models.BooleanField(default=True, verbose_name=_("是否可被继承"))

    class Meta:
        db_table = "sys_permission_set"
        verbose_name = _("权限集")
        verbose_name_plural = _("权限集")

    def __str__(self):
        company_name = self.company.company_name if self.company else _("全局")
        return f"{company_name} - {self.set_name}"


class SysPermission(BaseModel):
    """
    统一权限模型 - 定义对某个资源的具体操作权限
    权限集与权限是多对多关系，通过中间表关联
    """

    # 操作权限类型
    PERM_READ = "read"  # 查看
    PERM_WRITE = "write"  # 新增/编辑
    PERM_DELETE = "delete"  # 删除
    PERM_EXPORT = "export"  # 导出
    PERM_IMPORT = "import"  # 导入
    PERM_MANAGE = "manage"  # 管理

    PERM_TYPE_CHOICES = (
        (PERM_READ, _("查看")),
        (PERM_WRITE, _("编辑")),
        (PERM_DELETE, _("删除")),
        (PERM_EXPORT, _("导出")),
        (PERM_IMPORT, _("导入")),
        (PERM_MANAGE, _("管理")),
    )

    permission_id = models.AutoField(primary_key=True, verbose_name=_("权限ID"))

    company = models.ForeignKey(
        "SysCompany",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="company_permissions",
        verbose_name=_("所属公司"),
        help_text=_("为空时代表全局"),
    )

    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    resource = GenericForeignKey("content_type", "object_id")

    permission_code = models.CharField(max_length=50, verbose_name=_("权限编码"))
    permission_name = models.CharField(max_length=100, verbose_name=_("权限名称"))
    permission_type = models.CharField(
        max_length=20, choices=PERM_TYPE_CHOICES, verbose_name=_("权限类型")
    )
    # 关联数据范围
    data_scope = models.ForeignKey(
        "SysDataScope",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name=_("数据范围"),
        help_text=_("仅对数据表资源有效"),
    )
    description = models.TextField(blank=True, verbose_name=_("权限描述"))

    class Meta:
        db_table = "sys_permission"
        verbose_name = _("系统权限")
        verbose_name_plural = _("系统权限")
        unique_together = ("content_type", "object_id", "company", "permission_type")

    def covers(self, target_perm_type: str) -> bool:
        """
        判断当前权限是否足以覆盖目标权限类型。
        - 'manage' 覆盖所有权限；
        - 其他权限仅当类型完全匹配时生效。
        """
        if self.permission_type == self.PERM_MANAGE:
            return True
        return self.permission_type == target_perm_type

    def clean(self):
        if self.company is None:
            if SysPermission.objects.filter(
                content_type=self.content_type,
                object_id=self.object_id,
                permission_type=self.permission_type,
                company__isnull=True,
            ).exists():
                raise ValidationError("全局权限已存在，不可重复创建。")

    def __str__(self):
        return f"{self.resource.resource_name}.{self.permission_name}"


class SysPermissionSetItem(BaseModel):
    """
    权限集项 - 权限集与权限的关联关系
    定义某个权限集包含哪些具体权限
    """

    permission_set = models.ForeignKey(
        SysPermissionSet,
        on_delete=models.CASCADE,
        related_name="permission_items",
        verbose_name=_("权限集"),
    )
    permission = models.ForeignKey(
        SysPermission,
        on_delete=models.CASCADE,
        related_name="set_items",
        verbose_name=_("权限"),
    )
    # 可以设置权限的有效期等扩展属性
    valid_from = models.DateTimeField(null=True, blank=True, verbose_name=_("生效时间"))
    valid_to = models.DateTimeField(null=True, blank=True, verbose_name=_("失效时间"))

    class Meta:
        db_table = "sys_permission_set_item"
        verbose_name = _("权限集项")
        verbose_name_plural = _("权限集项")
        unique_together = ("permission_set", "permission")

    def __str__(self):
        return f"{self.permission_set.set_name} - {self.permission}"


class SysUserDirectPermission(BaseModel):
    """用户直接权限关联"""

    user = models.ForeignKey(
        "SysUser", on_delete=models.CASCADE, verbose_name=_("用户")
    )
    permission = models.ForeignKey(
        SysPermission, on_delete=models.CASCADE, verbose_name=_("权限")
    )
    company = models.ForeignKey(
        "SysCompany",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="user_direct_permissions",
        verbose_name=_("所属公司"),
        help_text=_("为空时代表全局"),
    )

    assigned_by = models.ForeignKey(
        "SysUser",
        on_delete=models.SET_NULL,
        null=True,
        related_name="assigned_direct_permissions",
        verbose_name=_("分配人"),
    )
    valid_from = models.DateTimeField(null=True, blank=True, verbose_name=_("生效时间"))
    valid_to = models.DateTimeField(null=True, blank=True, verbose_name=_("失效时间"))

    class Meta:
        db_table = "sys_user_direct_permission"
        verbose_name = _("用户直接权限")
        verbose_name_plural = _("用户直接权限")
        unique_together = ("user", "permission")

    def __str__(self):
        return f"{self.user.cn_name} - {self.permission}"


# class SysFieldPermission(BaseModel):
#     """
#     字段权限控制模型 - 控制角色对具体字段的访问权限
#     """

#     # 权限类型
#     PERM_READ = 1  # 读取
#     PERM_WRITE = 2  # 写入
#     # PERM_EXPORT = "export"  # 导出
#     # PERM_SEARCH = "search"  # 搜索

#     PERMISSION_CHOICES = (
#         (PERM_READ, _("读取")),
#         (PERM_WRITE, _("写入")),
#         # (PERM_EXPORT, _("导出")),
#         # (PERM_SEARCH, _("搜索")),
#     )

#     company = models.ForeignKey(
#         "SysCompany",
#         on_delete=models.CASCADE,
#         null=True,
#         blank=True,
#         related_name="field_permissions",
#         verbose_name=_("所属公司"),
#     )

#     role = models.ForeignKey(
#         "SysRole",
#         on_delete=models.CASCADE,
#         related_name="field_permissions",
#         verbose_name=_("角色"),
#     )
#     field_resource = models.ForeignKey(
#         SysResource,
#         on_delete=models.CASCADE,
#         limit_choices_to={"resource_type": SysResource.RESOURCE_FIELD},
#         related_name="role_permissions",
#         verbose_name=_("字段资源"),
#     )
#     permission_type = models.CharField(
#         max_length=20, choices=PERMISSION_CHOICES, verbose_name=_("权限类型")
#     )
#     is_granted = models.BooleanField(default=True, verbose_name=_("是否授权"))

#     # 条件限制（JSON格式，用于复杂权限控制）
#     condition = models.JSONField(
#         default=dict,
#         blank=True,
#         verbose_name=_("条件限制"),
#         help_text=_("JSON格式的条件限制，如：{'min_value': 0, 'max_value': 100}"),
#     )

#     class Meta:
#         db_table = "sys_field_permission"
#         verbose_name = _("字段权限")
#         verbose_name_plural = _("字段权限")
#         unique_together = ("role", "field_resource", "permission_type")
#         ordering = ["role", "field_resource", "permission_type"]

#     def __str__(self):
#         status = _("允许") if self.is_granted else _("拒绝")
#         return f"{self.role.role_name} - {self.field_resource.resource_name} - {self.get_permission_type_display()} ({status})"

#     @classmethod
#     def check_field_permission(
#         cls, user: SysUser, table_name, field_name, permission_type, company_pk=None
#     ):
#         """
#         检查用户对指定字段的权限
#         """
#         # 超级用户拥有所有权限
#         if user.is_superuser:
#             return True

#         if not company_pk:
#             user_company = user.get_company()
#             company_pk = user_company.pk if user_company else None

#         if company_pk and not user.is_in_company_tree(company_pk):
#             return False

#         # 获取表资源
#         table_resource_qs = SysResource.objects.filter(
#             resource_type=SysResource.RESOURCE_TABLE,
#             table_name=table_name,
#             is_active=True,
#         )

#         if company_pk:
#             table_resource_qs = table_resource_qs.filter(company__pk=company_pk)

#         table_resource = table_resource_qs.first()

#         if not table_resource:
#             return False

#         # 获取字段资源
#         field_resource = table_resource.get_field_resource(field_name)
#         if not field_resource:
#             return False

#         # 检查用户的所有角色
#         for user_role in user.get_all_roles():
#             if company_pk and user_role.company and user_role.company.pk != company_pk:
#                 continue
#             has_perm = cls._check_role_field_permission(
#                 user_role, field_resource, permission_type
#             )
#             if has_perm:
#                 return True

#         return False

#     @classmethod
#     def _check_role_field_permission(cls, role, field_resource, permission_type):
#         """检查角色对字段的权限"""
#         try:
#             perm = cls.objects.get(
#                 role=role,
#                 field_resource=field_resource,
#                 permission_type=permission_type,
#                 is_active=True,
#             )
#             return perm.is_granted
#         except cls.DoesNotExist:
#             # 如果没有明确设置权限，默认拒绝
#             return False

#     def get_condition_expression(self):
#         """获取条件限制的表达式"""
#         if not self.condition:
#             return None

#         # 这里可以根据业务需求解析条件
#         # 例如：返回Q对象用于QuerySet过滤
#         return self._parse_condition_to_q()

#     def _parse_condition_to_q(self):
#         """将条件解析为Django Q对象"""

#         conditions = Q()

#         for key, value in self.condition.items():
#             if key == "min_value":
#                 conditions &= Q(**{f"{self.field_resource.field_name}__gte": value})
#             elif key == "max_value":
#                 conditions &= Q(**{f"{self.field_resource.field_name}__lte": value})
#             elif key == "allowed_values":
#                 conditions &= Q(**{f"{self.field_resource.field_name}__in": value})
#             elif key == "excluded_values":
#                 conditions &= ~Q(**{f"{self.field_resource.field_name}__in": value})

#         return conditions
