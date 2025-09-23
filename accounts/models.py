"""
系统权限模型定义
"""

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _


class BaseModel(models.Model):
    """抽象基模型，提供公共字段和方法"""

    created_time = models.DateTimeField(auto_now_add=True, verbose_name=_("创建时间"))
    updated_time = models.DateTimeField(auto_now=True, verbose_name=_("更新时间"))
    is_active = models.BooleanField(default=True, verbose_name=_("是否激活"))

    class Meta:
        abstract = True


class SysMenu(BaseModel):
    """系统菜单模型"""

    # 菜单类型选择
    MENU_TYPE_SIDEBAR = 1
    MENU_TYPE_TOP = 2
    MENU_TYPE_BUTTON = 3
    MENU_TYPE_API = 4

    MENU_TYPE_CHOICES = (
        (MENU_TYPE_SIDEBAR, _("侧边栏菜单")),
        (MENU_TYPE_TOP, _("顶部菜单")),
        (MENU_TYPE_BUTTON, _("按钮菜单")),
        (MENU_TYPE_API, _("API菜单")),
    )

    menu_id = models.AutoField(primary_key=True, verbose_name=_("菜单ID"))
    parent_menu = models.ForeignKey(
        "self",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="children",
        verbose_name=_("父级菜单"),
    )
    menu_name = models.CharField(max_length=100, verbose_name=_("菜单名称"))
    menu_type = models.IntegerField(
        choices=MENU_TYPE_CHOICES, verbose_name=_("菜单类型")
    )
    menu_path = models.CharField(max_length=200, blank=True, verbose_name=_("菜单路径"))
    menu_icon = models.CharField(max_length=50, blank=True, verbose_name=_("菜单图标"))
    sort_order = models.IntegerField(default=0, verbose_name=_("排序序号"))
    permission_code = models.CharField(
        max_length=100, unique=True, verbose_name=_("权限标识码")
    )
    description = models.TextField(blank=True, verbose_name=_("菜单描述"))

    class Meta:
        db_table = "sys_menu"
        verbose_name = _("系统菜单")
        verbose_name_plural = _("系统菜单")
        ordering = ["sort_order", "menu_id"]

    def __str__(self):
        return f"{self.menu_name} ({self.get_menu_type_display()})"


class SysMetaTable(BaseModel):
    """元数据表模型"""

    table_id = models.AutoField(primary_key=True, verbose_name=_("表ID"))
    table_name = models.CharField(max_length=100, unique=True, verbose_name=_("表名"))
    table_description = models.CharField(max_length=200, verbose_name=_("表描述"))
    app_label = models.CharField(max_length=50, verbose_name=_("应用标签"))

    class Meta:
        db_table = "sys_meta_table"
        verbose_name = _("元数据表")
        verbose_name_plural = _("元数据表")

    def __str__(self):
        return f"{self.table_name} ({self.table_description})"


class SysMetaColumn(BaseModel):
    """元数据列模型"""

    # 字段类型选择
    FIELD_TYPE_CHAR = 1
    FIELD_TYPE_INT = 2
    FIELD_TYPE_FLOAT = 3
    FIELD_TYPE_DATE = 4
    FIELD_TYPE_DATETIME = 5
    FIELD_TYPE_BOOL = 6
    FIELD_TYPE_TEXT = 7

    FIELD_TYPE_CHOICES = (
        (FIELD_TYPE_CHAR, _("字符型")),
        (FIELD_TYPE_INT, _("整型")),
        (FIELD_TYPE_FLOAT, _("浮点型")),
        (FIELD_TYPE_DATE, _("日期型")),
        (FIELD_TYPE_DATETIME, _("日期时间型")),
        (FIELD_TYPE_BOOL, _("布尔型")),
        (FIELD_TYPE_TEXT, _("文本型")),
    )

    column_id = models.AutoField(primary_key=True, verbose_name=_("字段ID"))
    table = models.ForeignKey(
        SysMetaTable,
        on_delete=models.CASCADE,
        related_name="columns",
        verbose_name=_("所属数据表"),
    )
    column_name = models.CharField(max_length=100, verbose_name=_("字段名"))
    column_label = models.CharField(max_length=100, verbose_name=_("字段标签"))
    field_type = models.IntegerField(
        choices=FIELD_TYPE_CHOICES, verbose_name=_("字段类型")
    )
    is_sensitive = models.BooleanField(default=False, verbose_name=_("是否敏感字段"))
    description = models.TextField(blank=True, verbose_name=_("字段描述"))

    class Meta:
        db_table = "sys_meta_column"
        verbose_name = _("元数据列")
        verbose_name_plural = _("元数据列")
        unique_together = ("table", "column_name")

    def __str__(self):
        return f"{self.column_label} ({self.column_name})"


class SysRole(BaseModel):
    """系统角色模型"""

    role_id = models.AutoField(primary_key=True, verbose_name=_("角色ID"))
    role_name = models.CharField(max_length=50, unique=True, verbose_name=_("角色名称"))
    role_code = models.CharField(max_length=50, unique=True, verbose_name=_("角色编码"))
    role_level = models.IntegerField(
        default=1,
        validators=[MinValueValidator(1), MaxValueValidator(10)],
        verbose_name=_("角色级别"),
    )
    description = models.TextField(blank=True, verbose_name=_("角色描述"))
    # 移除原来的 JSONField，通过关联表实现更规范的权限管理

    class Meta:
        db_table = "sys_role"
        verbose_name = _("系统角色")
        verbose_name_plural = _("系统角色")
        ordering = ["role_level", "role_id"]

    def __str__(self):
        return str(self.role_name)


class SysUser(BaseModel):
    """系统用户模型"""

    user_id = models.AutoField(primary_key=True, verbose_name=_("用户ID"))
    username = models.CharField(max_length=50, unique=True, verbose_name=_("用户名"))
    user_name = models.CharField(max_length=100, verbose_name=_("显示名称"))
    email = models.EmailField(verbose_name=_("邮箱"))
    is_superuser = models.BooleanField(default=False, verbose_name=_("是否超级用户"))
    last_login = models.DateTimeField(
        null=True, blank=True, verbose_name=_("最后登录时间")
    )

    class Meta:
        db_table = "sys_user"
        verbose_name = _("系统用户")
        verbose_name_plural = _("系统用户")

    def __str__(self):
        return str(self.user_name)


class SysUserRole(BaseModel):
    """用户角色关联模型"""

    user = models.ForeignKey(
        SysUser,
        on_delete=models.CASCADE,
        related_name="user_roles",
        verbose_name=_("用户"),
    )
    role = models.ForeignKey(
        SysRole,
        on_delete=models.CASCADE,
        related_name="role_users",
        verbose_name=_("角色"),
    )
    assigned_by = models.ForeignKey(
        SysUser,
        on_delete=models.SET_NULL,
        null=True,
        related_name="assigned_roles",
        verbose_name=_("分配人"),
    )

    class Meta:
        db_table = "sys_user_role"
        verbose_name = _("用户角色关联")
        verbose_name_plural = _("用户角色关联记录")
        unique_together = ("user", "role")

    def __str__(self):
        return f"{self.user.user_name} - {self.role.role_name}"


class SysRoleMenuPermission(BaseModel):
    """角色菜单权限模型"""

    # 权限级别选择
    PERM_LEVEL_READ = 1
    PERM_LEVEL_WRITE = 2
    PERM_LEVEL_DELETE = 3
    PERM_LEVEL_ADMIN = 4

    PERM_LEVEL_CHOICES = (
        (PERM_LEVEL_READ, _("只读")),
        (PERM_LEVEL_WRITE, _("可写")),
        (PERM_LEVEL_DELETE, _("可删除")),
        (PERM_LEVEL_ADMIN, _("管理")),
    )

    role = models.ForeignKey(
        SysRole,
        on_delete=models.CASCADE,
        related_name="menu_permissions",
        verbose_name=_("角色"),
    )
    menu = models.ForeignKey(
        SysMenu,
        on_delete=models.CASCADE,
        related_name="role_permissions",
        verbose_name=_("菜单"),
    )
    permission_level = models.IntegerField(
        choices=PERM_LEVEL_CHOICES, default=PERM_LEVEL_READ, verbose_name=_("权限级别")
    )
    is_granted = models.BooleanField(default=True, verbose_name=_("是否授权"))

    class Meta:
        db_table = "sys_role_menu_permission"
        verbose_name = _("角色菜单权限")
        verbose_name_plural = _("角色菜单权限")
        unique_together = ("role", "menu")

    def __str__(self):
        return (
            f"{self.role.role_name} - "
            f"{self.menu.menu_name} "
            f"({self.get_permission_level_display()})"
        )


class SysRoleColumnPermission(BaseModel):
    """角色字段权限模型"""

    role = models.ForeignKey(
        SysRole,
        on_delete=models.CASCADE,
        related_name="column_permissions",
        verbose_name=_("角色"),
    )
    column = models.ForeignKey(
        SysMetaColumn,
        on_delete=models.CASCADE,
        related_name="role_permissions",
        verbose_name=_("数据字段"),
    )
    can_read = models.BooleanField(default=True, verbose_name=_("可读"))
    can_write = models.BooleanField(default=False, verbose_name=_("可写"))
    can_export = models.BooleanField(default=False, verbose_name=_("可导出"))

    class Meta:
        db_table = "sys_role_column_permission"
        verbose_name = _("角色字段权限")
        verbose_name_plural = _("角色字段权限")
        unique_together = ("role", "column")

    def __str__(self):
        permissions = []
        if self.can_read:
            permissions.append("读")
        if self.can_write:
            permissions.append("写")
        if self.can_export:
            permissions.append("导出")
        return f"{self.role.role_name} - {self.column.column_label} ({''.join(permissions)})"


class SysRoleResourcePermission(BaseModel):
    """角色资源权限模型"""

    # 资源类型选择
    RESOURCE_API = 1
    RESOURCE_FILE = 2
    RESOURCE_BUTTON = 3
    RESOURCE_REPORT = 4

    RESOURCE_TYPE_CHOICES = (
        (RESOURCE_API, _("API接口")),
        (RESOURCE_FILE, _("文件")),
        (RESOURCE_BUTTON, _("按钮")),
        (RESOURCE_REPORT, _("报表")),
    )

    role = models.ForeignKey(
        SysRole,
        on_delete=models.CASCADE,
        related_name="resource_permissions",
        verbose_name=_("角色"),
    )
    resource_type = models.IntegerField(
        choices=RESOURCE_TYPE_CHOICES, verbose_name=_("资源类型")
    )
    resource_code = models.CharField(max_length=100, verbose_name=_("资源标识码"))
    resource_name = models.CharField(max_length=100, verbose_name=_("资源名称"))
    permission_level = models.IntegerField(
        choices=SysRoleMenuPermission.PERM_LEVEL_CHOICES, verbose_name=_("权限级别")
    )
    extra_config = models.JSONField(
        default=dict, blank=True, verbose_name=_("额外配置")
    )

    class Meta:
        db_table = "sys_role_resource_permission"
        verbose_name = _("角色资源权限")
        verbose_name_plural = _("角色资源权限")
        unique_together = ("role", "resource_type", "resource_code")

    def __str__(self):
        return (
            f"{self.role.role_name} - "
            f"{self.resource_name} "
            f"({self.get_permission_level_display()})"
        )
