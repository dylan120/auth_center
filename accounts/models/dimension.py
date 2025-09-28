from django.db import models
from django.utils.translation import gettext_lazy as _

from accounts.models import BaseModel


# 新增维度配置模型
class SysDimension(BaseModel):
    """
    维度定义表 - 存储所有可用的维度类型（如投放方式、素材来源等）
    """

    dimension_id = models.AutoField(primary_key=True, verbose_name=_("维度ID"))
    dimension_name = models.CharField(max_length=100, verbose_name=_("维度名称"))
    dimension_code = models.CharField(
        max_length=50, unique=True, verbose_name=_("维度编码")
    )
    description = models.TextField(blank=True, verbose_name=_("维度描述"))

    class Meta:
        db_table = "sys_dimension"
        verbose_name = _("维度定义")
        verbose_name_plural = _("维度定义")
        ordering = ["dimension_code"]

    def __str__(self):
        return f"{self.dimension_name} ({self.dimension_code})"


class SysDimensionOption(BaseModel):
    """
    维度选项表 - 存储每个维度的可选值（如投放方式包含信息流、直播流等）
    """

    option_id = models.AutoField(primary_key=True, verbose_name=_("选项ID"))
    dimension = models.ForeignKey(
        SysDimension,
        on_delete=models.CASCADE,
        related_name="options",
        verbose_name=_("所属维度"),
    )
    option_name = models.CharField(max_length=100, verbose_name=_("选项名称"))
    option_value = models.CharField(max_length=50, verbose_name=_("选项值"))
    sort_order = models.IntegerField(default=0, verbose_name=_("排序序号"))

    class Meta:
        db_table = "sys_dimension_option"
        verbose_name = _("维度选项")
        verbose_name_plural = _("维度选项")
        unique_together = ("dimension", "option_value")
        ordering = ["dimension", "sort_order"]

    def __str__(self):
        return f"{self.dimension.dimension_name}: {self.option_name}"


class SysTableDimension(BaseModel):
    """
    表维度配置表 - 关联数据表资源与维度，定义哪些表需要哪些维度
    """

    table = models.ForeignKey(
        "SysTableResource",
        on_delete=models.CASCADE,
        related_name="dimensions",
        verbose_name=_("数据表资源"),
    )
    dimension = models.ForeignKey(
        SysDimension, on_delete=models.CASCADE, verbose_name=_("维度")
    )
    is_required = models.BooleanField(default=False, verbose_name=_("是否必填维度"))
    default_option = models.ForeignKey(
        SysDimensionOption,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name=_("默认选项"),
    )

    class Meta:
        db_table = "sys_table_dimension"
        verbose_name = _("表维度配置")
        verbose_name_plural = _("表维度配置")
        unique_together = ("table", "dimension")

    def __str__(self):
        return f"{self.table.table_name} - {self.dimension.dimension_name}"


class SysPermissionSetItemDimensionOption(BaseModel):
    """
    权限集项与维度选项的关联表（替代 ManyToMany）
    """

    permission_set_item = models.ForeignKey(
        "SysPermissionSetItem",
        on_delete=models.CASCADE,
        related_name="dimension_option_relations",
        verbose_name=_("权限集项"),
    )
    dimension_option = models.ForeignKey(
        SysDimensionOption,
        on_delete=models.CASCADE,
        related_name="permission_set_item_relations",
        verbose_name=_("维度选项"),
    )

    class Meta:
        db_table = "sys_permission_set_item_dimension_option"
        verbose_name = _("权限集项-维度选项关联")
        verbose_name_plural = _("权限集项-维度选项关联")
        unique_together = ("permission_set_item", "dimension_option")

    def __str__(self):
        return f"{self.permission_set_item} → {self.dimension_option}"


class SysUserDirectPermissionDimensionOption(BaseModel):
    """
    用户直接权限与维度选项的关联表（替代 ManyToMany）
    """

    user_direct_permission = models.ForeignKey(
        "SysUserDirectPermission",
        on_delete=models.CASCADE,
        related_name="dimension_option_relations",
        verbose_name=_("用户直接权限"),
    )
    dimension_option = models.ForeignKey(
        SysDimensionOption,
        on_delete=models.CASCADE,
        related_name="user_direct_permission_relations",
        verbose_name=_("维度选项"),
    )

    class Meta:
        db_table = "sys_user_direct_permission_dimension_option"
        verbose_name = _("用户直接权限-维度选项关联")
        verbose_name_plural = _("用户直接权限-维度选项关联")
        unique_together = ("user_direct_permission", "dimension_option")

    def __str__(self):
        return f"{self.user_direct_permission} → {self.dimension_option}"
