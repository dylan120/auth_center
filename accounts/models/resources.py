from django.db import models

from accounts.models import BaseModel


class SysDataScope(BaseModel):
    """
    数据权限范围定义 - 简化版：只支持全部数据和仅本人数据
    """

    # 数据范围类型（简化版）
    SCOPE_ALL = 1  # 全部数据
    SCOPE_SELF = 2  # 仅本人数据
    SCOPE_DEPT = 3  # 仅部门数据
    # SCOPE_CUSTOM = 3  # 自定义范围（可选）

    SCOPE_TYPE_CHOICES = (
        (SCOPE_ALL, _("全部数据")),
        (SCOPE_SELF, _("仅本人数据")),
        (SCOPE_DEPT, _("部门数据")),
        # (SCOPE_CUSTOM, _("自定义范围")),
    )

    scope_id = models.AutoField(primary_key=True, verbose_name=_("数据范围ID"))
    scope_name = models.CharField(
        max_length=100, unique=True, verbose_name=_("范围名称")
    )
    scope_code = models.CharField(
        max_length=50, unique=True, verbose_name=_("范围编码")
    )
    scope_type = models.IntegerField(
        choices=SCOPE_TYPE_CHOICES, verbose_name=_("范围类型")
    )

    # 自定义SQL条件（用于SCOPE_CUSTOM类型）
    # custom_sql = models.TextField(blank=True, verbose_name=_("自定义SQL条件"))
    description = models.TextField(blank=True, verbose_name=_("范围描述"))

    class Meta:
        db_table = "sys_data_scope"
        verbose_name = _("数据范围")
        verbose_name_plural = _("数据范围")

    def __str__(self):
        return f"{self.scope_name} ({self.get_scope_type_display()})"


class SysResource(BaseModel):
    """
    统一资源模型 - 所有需要权限控制的资源都在这里定义
    支持菜单、API、按钮、数据字段、文件等各种资源类型
    """

    # 资源类型
    RESOURCE_MENU = "menu"  # 菜单
    RESOURCE_API = "api"  # API接口
    RESOURCE_FIELD = "field"  # 数据字段
    RESOURCE_MODULE = "module"  # 业务模块
    RESOURCE_TABLE = "table"  # 数据表资源

    RESOURCE_TYPE_CHOICES = (
        (RESOURCE_MENU, _("菜单")),
        (RESOURCE_API, _("API接口")),
        (RESOURCE_FIELD, _("数据字段")),
        (RESOURCE_MODULE, _("业务模块")),
        (RESOURCE_TABLE, _("数据表")),
    )

    resource_id = models.AutoField(primary_key=True, verbose_name=_("资源ID"))
    resource_name = models.CharField(max_length=100, verbose_name=_("资源名称"))
    resource_code = models.CharField(
        max_length=100, unique=True, verbose_name=_("资源编码")
    )
    resource_type = models.CharField(
        max_length=20, choices=RESOURCE_TYPE_CHOICES, verbose_name=_("资源类型")
    )

    # 通用属性字段，根据资源类型不同含义不同
    path = models.CharField(
        max_length=200, blank=True, verbose_name=_("路径/URL")
    )  # 菜单路径或API路径
    icon = models.CharField(
        max_length=50, blank=True, verbose_name=_("图标")
    )  # 菜单图标
    component = models.CharField(
        max_length=100, blank=True, verbose_name=_("组件")
    )  # 前端组件
    method = models.CharField(
        max_length=10, blank=True, verbose_name=_("HTTP方法")
    )  # API方法 GET/POST等

    # 数据表相关属性（用于RESOURCE_TABLE类型）
    table_name = models.CharField(max_length=100, blank=True, verbose_name=_("表名"))
    model_class = models.CharField(max_length=200, blank=True, verbose_name=_("模型类"))
    # 标识创建人字段名（用于SCOPE_SELF数据范围）
    creator_field = models.CharField(
        max_length=100, blank=True, default="created_by", verbose_name=_("创建人字段")
    )

    # 字段资源相关属性（用于RESOURCE_FIELD类型）
    parent_resource = models.ForeignKey(
        "self",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="child_fields",
        verbose_name=_("所属表资源"),
        help_text=_("字段资源必须属于一个表资源"),
    )
    field_name = models.CharField(max_length=100, blank=True, verbose_name=_("字段名"))
    field_type = models.CharField(max_length=50, blank=True, verbose_name=_("字段类型"))
    is_sensitive = models.BooleanField(default=False, verbose_name=_("是否敏感字段"))

    sort_order = models.IntegerField(default=0, verbose_name=_("排序序号"))
    description = models.TextField(blank=True, verbose_name=_("资源描述"))

    class Meta:
        db_table = "sys_resource"
        verbose_name = _("系统资源")
        verbose_name_plural = _("系统资源")
        ordering = ["resource_type", "sort_order", "resource_id"]

    def __str__(self):
        return f"{self.resource_name} ({self.get_resource_type_display()})"

    def get_table_fields(self):
        """获取表的所有字段资源"""
        if self.resource_type != self.RESOURCE_TABLE:
            return []
        return self.child_fields.filter(is_active=True)

    def get_field_resource(self, field_name):
        """获取指定字段的资源对象"""
        return self.child_fields.filter(field_name=field_name, is_active=True).first()

    def is_table_resource(self):
        """判断是否是表资源"""
        return self.resource_type == self.RESOURCE_TABLE

    def is_field_resource(self):
        """判断是否是字段资源"""
        return self.resource_type == self.RESOURCE_FIELD
