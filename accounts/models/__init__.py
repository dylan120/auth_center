"""
base model
"""

from django.db import models
from django.utils.translation import gettext_lazy as _

from common.utils.model_loader import auto_discover_models


class BaseModel(models.Model):
    """抽象基模型，提供公共字段"""

    created_time = models.DateTimeField(auto_now_add=True, verbose_name=_("创建时间"))
    updated_time = models.DateTimeField(auto_now=True, verbose_name=_("更新时间"))
    is_active = models.BooleanField(default=True, verbose_name=_("是否激活"))

    class Meta:
        abstract = True


class CompanyDataModel(models.Model):
    """抽象基模型，公司级别的数据表"""

    company = models.ForeignKey(
        "SysCompany",
        on_delete=models.CASCADE,
        verbose_name=_("公司主体"),
        related_name="%(class)s_related",
    )

    created_time = models.DateTimeField(auto_now_add=True, verbose_name=_("创建时间"))
    updated_time = models.DateTimeField(auto_now=True, verbose_name=_("更新时间"))

    class Meta:
        abstract = True


class UserDataModel(models.Model):
    """抽象基模型，用户级别的数据表"""

    created_by = models.ForeignKey(
        "SysUser",
        on_delete=models.CASCADE,
        verbose_name=_("创建人"),
        related_name="%(class)s_related",
    )

    created_time = models.DateTimeField(auto_now_add=True, verbose_name=_("创建时间"))
    updated_time = models.DateTimeField(auto_now=True, verbose_name=_("更新时间"))

    class Meta:
        abstract = True

    def is_creator(self, user):
        if user == self.created_by:
            return True


auto_discover_models("accounts", globals())
