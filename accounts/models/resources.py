from django.db import models
from django.utils.translation import gettext_lazy as _

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
    资源基类 - 所有资源类型的公共字段
    """

    # 资源所属公司（Null表示全局资源）
    company = models.ForeignKey(
        "SysCompany",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="resources",
        verbose_name=_("所属公司"),
    )

    # 资源类型
    RESOURCE_MENU = "menu"  # 菜单
    RESOURCE_API = "api"  # API接口
    RESOURCE_MODULE = "module"  # 业务模块
    RESOURCE_TABLE = "table"  # 数据表资源
    RESOURCE_FIELD = "field"  # 数据字段

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

    sort_order = models.IntegerField(default=0, verbose_name=_("排序序号"))
    description = models.TextField(blank=True, verbose_name=_("资源描述"))

    class Meta:
        abstract = True  # 设为抽象基类
        ordering = ["resource_type", "sort_order", "resource_id"]

    def __str__(self):
        return f"{self.resource_name} ({self.get_resource_type_display()})"


# 具体的资源类型表
class SysMenuResource(SysResource):
    """
    菜单资源表
    """

    # 菜单特定字段
    path = models.CharField(max_length=200, verbose_name=_("菜单路径"))
    icon = models.CharField(max_length=50, blank=True, verbose_name=_("菜单图标"))
    component = models.CharField(max_length=100, verbose_name=_("前端组件"))
    parent_menu = models.ForeignKey(
        "self",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="children",
        verbose_name=_("父级菜单"),
    )
    # 菜单级别
    menu_level = models.IntegerField(default=1, verbose_name=_("菜单层级"))
    # 是否外链
    is_external = models.BooleanField(default=False, verbose_name=_("是否外链"))
    # 是否缓存
    keep_alive = models.BooleanField(default=True, verbose_name=_("是否缓存"))

    class Meta:
        db_table = "sys_menu_resource"
        verbose_name = _("菜单资源")
        verbose_name_plural = _("菜单资源")

    def save(self, *args, **kwargs):
        # 自动设置资源类型
        self.resource_type = SysResource.RESOURCE_MENU
        super().save(*args, **kwargs)


class SysApiResource(SysResource):
    """
    API接口资源表
    """

    # API特定字段
    path = models.CharField(max_length=200, verbose_name=_("API路径"))
    method = models.CharField(max_length=10, verbose_name=_("HTTP方法"))
    # API分组
    api_group = models.CharField(max_length=50, blank=True, verbose_name=_("API分组"))
    # 是否需要认证
    require_auth = models.BooleanField(default=True, verbose_name=_("需要认证"))
    # 是否记录日志
    log_enabled = models.BooleanField(default=True, verbose_name=_("记录日志"))
    # 请求频率限制（次/分钟）
    rate_limit = models.IntegerField(default=0, verbose_name=_("频率限制"))

    class Meta:
        db_table = "sys_api_resource"
        verbose_name = _("API资源")
        verbose_name_plural = _("API资源")
        unique_together = ("path", "method")  # 同一路径和方法不能重复

    def save(self, *args, **kwargs):
        self.resource_type = SysResource.RESOURCE_API
        super().save(*args, **kwargs)


class SysTableResource(SysResource):
    """
    数据表资源表
    """

    # 表特定字段
    table_name = models.CharField(max_length=100, unique=True, verbose_name=_("表名"))
    model_class = models.CharField(max_length=200, verbose_name=_("模型类"))
    # 标识创建人字段名
    creator_field = models.CharField(
        max_length=100, default="created_by", verbose_name=_("创建人字段")
    )
    # 表描述
    table_comment = models.TextField(blank=True, verbose_name=_("表注释"))
    # 是否系统表
    is_system_table = models.BooleanField(default=False, verbose_name=_("系统表"))
    # 数据保留策略（天）
    data_retention_days = models.IntegerField(default=0, verbose_name=_("数据保留天数"))

    class Meta:
        db_table = "sys_table_resource"
        verbose_name = _("表资源")
        verbose_name_plural = _("表资源")

    def save(self, *args, **kwargs):
        self.resource_type = SysResource.RESOURCE_TABLE
        super().save(*args, **kwargs)

    def get_fields(self):
        """获取表的所有字段资源"""
        return SysFieldResource.objects.filter(table_resource=self, is_active=True)

    def get_field_resource(self, field_name):
        """获取指定字段的资源对象"""
        return self.fields.filter(field_name=field_name, is_active=True).first()


class SysFieldResource(SysResource):
    """
    数据字段资源表
    """

    # 字段必须属于一个表资源
    table_resource = models.ForeignKey(
        SysTableResource,
        on_delete=models.CASCADE,
        related_name="fields",
        verbose_name=_("所属表资源"),
    )
    field_name = models.CharField(max_length=100, verbose_name=_("字段名"))
    field_type = models.CharField(max_length=50, verbose_name=_("字段类型"))
    # 字段显示名称
    field_label = models.CharField(max_length=100, verbose_name=_("字段标签"))
    # 是否敏感字段
    is_sensitive = models.BooleanField(default=False, verbose_name=_("敏感字段"))
    # 是否必填字段
    is_required = models.BooleanField(default=False, verbose_name=_("必填字段"))
    # 字段长度限制
    max_length = models.IntegerField(null=True, blank=True, verbose_name=_("最大长度"))
    # 字段默认值
    default_value = models.CharField(
        max_length=200, blank=True, verbose_name=_("默认值")
    )
    # 字段验证规则
    validation_rules = models.JSONField(
        default=dict, blank=True, verbose_name=_("验证规则")
    )

    class Meta:
        db_table = "sys_field_resource"
        verbose_name = _("字段资源")
        verbose_name_plural = _("字段资源")
        unique_together = ("table_resource", "field_name")

    def save(self, *args, **kwargs):
        self.resource_type = SysResource.RESOURCE_FIELD
        # 自动设置公司（从表资源继承）
        if not self.company and self.table_resource:
            self.company = self.table_resource.company
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.table_resource.table_name}.{self.field_name}"


class SysModuleResource(SysResource):
    """
    业务模块资源表
    """

    # 模块特定字段
    module_code = models.CharField(
        max_length=50, unique=True, verbose_name=_("模块编码")
    )
    # 模块版本
    version = models.CharField(max_length=20, default="1.0.0", verbose_name=_("版本号"))
    # 模块入口
    entry_point = models.CharField(max_length=200, blank=True, verbose_name=_("入口点"))
    # 依赖模块
    dependencies = models.JSONField(
        default=list, blank=True, verbose_name=_("依赖模块")
    )
    # 模块配置
    config = models.JSONField(default=dict, blank=True, verbose_name=_("模块配置"))
    # 是否启用
    is_enabled = models.BooleanField(default=True, verbose_name=_("是否启用"))

    class Meta:
        db_table = "sys_module_resource"
        verbose_name = _("模块资源")
        verbose_name_plural = _("模块资源")

    def save(self, *args, **kwargs):
        self.resource_type = SysResource.RESOURCE_MODULE
        super().save(*args, **kwargs)
