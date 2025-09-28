from django.db import models
from django.utils.translation import gettext_lazy as _


class SysDataScope(models.Model):
    """
    数据权限范围定义 - 简化版：只支持全部数据和仅本人数据
    """

    # 数据范围类型（简化版）
    SCOPE_SELF = 1  # 仅本人可见
    SCOPE_DEPT = 2  # 仅部门可见
    SCOPE_COMPANY = 3  # 公司内可见

    # SCOPE_CUSTOM = 3  # 自定义范围（可选）

    SCOPE_TYPE_CHOICES = (
        (SCOPE_SELF, _("仅本人可见")),
        (SCOPE_DEPT, _("仅部门可见")),
        (SCOPE_COMPANY, _("公司内可见")),
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
        return f"{self.scope_name}"
