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


# 修改原SysPermissionSetItem模型，关联维度选项
class SysPermissionSetItem(BaseModel):
    """
    权限集项 - 扩展支持维度选项
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
    # 新增：关联维度选项（多对多）
    dimension_options = models.ManyToManyField(
        SysDimensionOption,
        blank=True,
        related_name="permission_items",
        verbose_name=_("维度选项"),
    )
    valid_from = models.DateTimeField(null=True, blank=True, verbose_name=_("生效时间"))
    valid_to = models.DateTimeField(null=True, blank=True, verbose_name=_("失效时间"))

    class Meta:
        db_table = "sys_permission_set_item"
        verbose_name = _("权限集项")
        verbose_name_plural = _("权限集项")
        unique_together = ("permission_set", "permission")

    def __str__(self):
        return f"{self.permission_set.set_name} - {self.permission}"


# 修改原SysUserDirectPermission模型，关联维度选项
class SysUserDirectPermission(BaseModel):
    """用户直接权限关联 - 扩展支持维度选项"""

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
    # 新增：关联维度选项（多对多）
    dimension_options = models.ManyToManyField(
        SysDimensionOption,
        blank=True,
        related_name="user_direct_permissions",
        verbose_name=_("维度选项"),
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
