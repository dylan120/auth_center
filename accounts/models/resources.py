from django.apps import apps
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _

from accounts.models import BaseModel


class SysResource(BaseModel):
    """
    资源基类 - 所有资源类型的公共字段
    """

    # 资源类型
    RESOURCE_MENU = "menu"  # 菜单
    RESOURCE_MODULE = "module"  # 业务模块
    RESOURCE_TABLE = "table"  # 数据表资源
    RESOURCE_FIELD = "field"  # 数据字段
    # RESOURCE_API = "api"  # API接口

    RESOURCE_TYPE_CHOICES = (
        (RESOURCE_MENU, _("菜单")),
        # (RESOURCE_API, _("API接口")),
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
        return f"{self.resource_name} ({self.resource_code})"


# 具体的资源类型表
class SysMenuResource(SysResource):
    """
    菜单资源表
    """

    parent_id = models.IntegerField("父节点id", default=0)
    name = models.CharField("名称", max_length=50, db_index=True)
    url = models.CharField("访问地址带参数", max_length=400, blank=True, default="")
    url_path = models.CharField("访问路径", max_length=100, null=False, db_index=True)
    icon = models.CharField("图标", max_length=100, null=True, blank=True, default="")
    css = models.CharField("样式", max_length=100, null=True, blank=True, default="")
    order = models.IntegerField("排序", default=0)
    is_show = models.IntegerField("显示", default=1)
    is_log = models.IntegerField("记录日志", default=0)
    type = models.IntegerField("菜单类型", default=0)
    is_trace = models.IntegerField("跟踪", default=0)  # 0:否，1：是
    remark = models.CharField(
        "备注", max_length=10000, default="", null=True, blank=True
    )
    # objects = CacheManager
    level = models.IntegerField("权限等级", default=0)  # 1 ~ 5 数字越大，权限越高
    menu_type = models.IntegerField("菜单类型", default="0")  # 数据  操作

    class Meta:
        db_table = "sys_menu_resource"
        verbose_name = _("菜单资源")
        verbose_name_plural = _("菜单资源")

    def save(self, *args, **kwargs):
        # 自动设置资源类型
        self.resource_type = SysResource.RESOURCE_MENU
        super().save(*args, **kwargs)


class SysModuleResource(SysResource):
    """
    业务模块资源表
    """

    class Meta:
        db_table = "sys_module_resource"
        verbose_name = _("模块资源")
        verbose_name_plural = _("模块资源")

    def save(self, *args, **kwargs):
        self.resource_type = SysResource.RESOURCE_MODULE
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
    # 数据保留策略（天）
    data_retention_days = models.IntegerField(default=0, verbose_name=_("数据保留天数"))

    class Meta:
        db_table = "sys_table_resource"
        verbose_name = _("表资源")
        verbose_name_plural = _("表资源")

    def save(self, *args, **kwargs):
        self.resource_type = SysResource.RESOURCE_TABLE
        super().save(*args, **kwargs)

    # def get_model_class(self):
    #     """
    #     根据 model_class 字符串动态导入并返回模型类
    #     model_class 示例: 'myapp.MyModel'
    #     """
    #     try:
    #         app_label, model_name = self.model_class.rsplit(".", 1)
    #         # 使用 Django Apps registry 获取模型（推荐）
    #         return apps.get_model(app_label, model_name)
    #     except (ValueError, LookupError) as e:
    #         raise ValidationError(f"无法加载模型 {self.model_class}: {e}")

    # def get_fields(self):
    #     """
    #     动态获取该表资源对应模型的所有字段
    #     返回: [
    #         {'field_name': 'name', 'verbose_name': '姓名', 'type': 'CharField'},
    #         {'field_name': 'age', 'verbose_name': '年龄', 'type': 'IntegerField'},
    #         ...
    #     ]
    #     """
    #     model_cls = self.get_model_class()
    #     fields = []

    #     for field in model_cls._meta.get_fields():
    #         # 可以根据需要过滤字段，比如排除多对多、外键关系等
    #         if field.concrete:  # 只取数据库实际存在的字段
    #             fields.append(
    #                 {
    #                     "field_name": field.name,
    #                     "verbose_name": str(field.verbose_name).strip() or field.name,
    #                     "field_type": field.__class__.__name__,
    #                     # 可扩展：是否可编辑、是否必填等
    #                     "editable": getattr(field, "editable", True),
    #                     "blank": getattr(field, "blank", False),
    #                 }
    #             )

    #     return fields

    # def get_field_resource(self, field_name):
    #     """
    #     模拟返回一个“字段资源”对象（字典）
    #     """
    #     fields = self.get_fields()
    #     for field in fields:
    #         if field["field_name"] == field_name:
    #             return field
    #     return None

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

    class Meta:
        db_table = "sys_field_resource"
        verbose_name = _("字段资源")
        verbose_name_plural = _("字段资源")
        unique_together = ("table_resource", "field_name")

    def save(self, *args, **kwargs):
        self.resource_type = SysResource.RESOURCE_FIELD
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.table_resource.table_name}.{self.field_name}"


# class SysApiResource(SysResource):
#     """
#     API接口资源表
#     """

#     # API特定字段
#     path = models.CharField(max_length=200, verbose_name=_("API路径"))
#     method = models.CharField(max_length=10, verbose_name=_("HTTP方法"))
#     # API分组
#     api_group = models.CharField(max_length=50, blank=True, verbose_name=_("API分组"))
#     # 是否需要认证
#     require_auth = models.BooleanField(default=True, verbose_name=_("需要认证"))
#     # 是否记录日志
#     log_enabled = models.BooleanField(default=True, verbose_name=_("记录日志"))
#     # 请求频率限制（次/分钟）
#     rate_limit = models.IntegerField(default=0, verbose_name=_("频率限制"))

#     class Meta:
#         db_table = "sys_api_resource"
#         verbose_name = _("API资源")
#         verbose_name_plural = _("API资源")
#         unique_together = ("path", "method")  # 同一路径和方法不能重复

#     def save(self, *args, **kwargs):
#         self.resource_type = SysResource.RESOURCE_API
#         super().save(*args, **kwargs)
