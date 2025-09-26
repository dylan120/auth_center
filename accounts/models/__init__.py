from django.db import models
from django.utils.translation import gettext_lazy as _


class BaseModel(models.Model):
    """抽象基模型，提供公共字段"""

    created_time = models.DateTimeField(auto_now_add=True, verbose_name=_("创建时间"))
    updated_time = models.DateTimeField(auto_now=True, verbose_name=_("更新时间"))
    is_active = models.BooleanField(default=True, verbose_name=_("是否激活"))

    class Meta:
        abstract = True
