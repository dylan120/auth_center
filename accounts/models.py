"""
改进版权限系统模型设计 - 简化版数据查询控制
核心特性：
1. 统一的权限点管理，支持菜单、API、数据字段等多种资源类型
2. 基于权限集的角色管理
3. 简化用户操作，减少重复权限配置
4. 数据查询控制，支持仅查看自己数据和查看全部数据（
"""

from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import AbstractUser
from django.db import connection, models
from django.utils.translation import gettext_lazy as _


class BaseModel(models.Model):
    """抽象基模型，提供公共字段"""

    created_time = models.DateTimeField(auto_now_add=True, verbose_name=_("创建时间"))
    updated_time = models.DateTimeField(auto_now=True, verbose_name=_("更新时间"))
    is_active = models.BooleanField(default=True, verbose_name=_("是否激活"))

    class Meta:
        abstract = True


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
        return f"{self.set_name} ({self.get_set_type_display()})"


class SysDataScope(BaseModel):
    """
    数据权限范围定义 - 简化版：只支持全部数据和仅本人数据
    """

    # 数据范围类型（简化版）
    SCOPE_ALL = 1  # 全部数据
    SCOPE_SELF = 2  # 仅本人数据
    # SCOPE_CUSTOM = 3  # 自定义范围（可选）

    SCOPE_TYPE_CHOICES = (
        (SCOPE_ALL, _("全部数据")),
        (SCOPE_SELF, _("仅本人数据")),
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

    sort_order = models.IntegerField(default=0, verbose_name=_("排序序号"))
    description = models.TextField(blank=True, verbose_name=_("资源描述"))

    class Meta:
        db_table = "sys_resource"
        verbose_name = _("系统资源")
        verbose_name_plural = _("系统资源")
        ordering = ["resource_type", "sort_order", "resource_id"]

    def __str__(self):
        return f"{self.resource_name} ({self.get_resource_type_display()})"


class SysPermission(BaseModel):
    """
    统一权限模型 - 定义对某个资源的具体操作权限
    权限集与权限是多对多关系，通过中间表关联
    """

    # 操作权限类型
    PERM_READ = 1  # 查看
    PERM_WRITE = 2  # 新增/编辑
    PERM_DELETE = 3  # 删除
    PERM_EXPORT = 4  # 导出
    PERM_IMPORT = 5  # 导入
    PERM_EXECUTE = 6  # 执行
    PERM_MANAGE = 99  # 管理

    PERM_TYPE_CHOICES = (
        (PERM_READ, _("查看")),
        (PERM_WRITE, _("编辑")),
        (PERM_DELETE, _("删除")),
        (PERM_EXPORT, _("导出")),
        (PERM_IMPORT, _("导入")),
        (PERM_EXECUTE, _("执行")),
        (PERM_MANAGE, _("管理")),
    )

    permission_id = models.AutoField(primary_key=True, verbose_name=_("权限ID"))
    resource = models.ForeignKey(
        SysResource,
        on_delete=models.CASCADE,
        related_name="permissions",
        verbose_name=_("资源"),
    )
    permission_code = models.CharField(max_length=50, verbose_name=_("权限编码"))
    permission_name = models.CharField(max_length=100, verbose_name=_("权限名称"))
    permission_type = models.IntegerField(
        choices=PERM_TYPE_CHOICES, verbose_name=_("权限类型")
    )
    # 关联数据范围
    data_scope = models.ForeignKey(
        SysDataScope,
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
        unique_together = ("resource", "permission_type")

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


class SysRole(BaseModel):
    """
    系统角色模型 - 简化版，通过权限集来管理权限
    """

    role_id = models.AutoField(primary_key=True, verbose_name=_("角色ID"))
    role_name = models.CharField(max_length=50, unique=True, verbose_name=_("角色名称"))
    role_code = models.CharField(max_length=50, unique=True, verbose_name=_("角色编码"))
    description = models.TextField(blank=True, verbose_name=_("角色描述"))

    # 角色关联的权限集（多对多）
    permission_sets = models.ManyToManyField(
        SysPermissionSet,
        through="SysRolePermissionSet",
        related_name="roles",
        verbose_name=_("权限集"),
    )

    class Meta:
        db_table = "sys_role"
        verbose_name = _("系统角色")
        verbose_name_plural = _("系统角色")
        ordering = ["role_name", "role_id"]

    def __str__(self):
        return self.role_name

    def get_all_permissions(self):
        """获取角色所有权限（聚合所有权限集的权限）"""

        # 使用原生SQL查询提高性能
        sql = """
        SELECT DISTINCT 
            p.permission_id, p.permission_code, p.permission_name, 
            p.permission_type, p.data_scope_id,
            r.resource_id, r.resource_name, r.resource_type,
            r.path, r.table_name, r.model_class, r.creator_field,
            ds.scope_type as data_scope_type, ds.custom_sql as data_scope_sql
        FROM sys_role role
        JOIN sys_role_permission_set rps ON role.role_id = rps.role_id
        JOIN sys_permission_set ps ON rps.permission_set_id = ps.set_id
        JOIN sys_permission_set_item psi ON ps.set_id = psi.permission_set_id
        JOIN sys_permission p ON psi.permission_id = p.permission_id
        JOIN sys_resource r ON p.resource_id = r.resource_id
        LEFT JOIN sys_data_scope ds ON p.data_scope_id = ds.scope_id
        WHERE role.role_id = %s AND role.is_active = TRUE 
          AND ps.is_active = TRUE AND psi.is_active = TRUE 
          AND p.is_active = TRUE AND r.is_active = TRUE
        """

        with connection.cursor() as cursor:
            cursor.execute(sql, [self.role_id])
            columns = [col[0] for col in cursor.description]
            permissions = [dict(zip(columns, row)) for row in cursor.fetchall()]

        return permissions


class SysRolePermissionSet(BaseModel):
    """
    角色与权限集的关联关系
    """

    role = models.ForeignKey(SysRole, on_delete=models.CASCADE, verbose_name=_("角色"))
    permission_set = models.ForeignKey(
        SysPermissionSet, on_delete=models.CASCADE, verbose_name=_("权限集")
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


class SysUser(AbstractUser):
    """系统用户模型"""

    cn_name = models.CharField(max_length=100, verbose_name=_("显示名称"))

    # 用户直接关联的权限（用于特殊权限，优先级高于角色权限）
    direct_permissions = models.ManyToManyField(
        SysPermission,
        through="SysUserDirectPermission",
        through_fields=("user", "permission"),
        related_name="direct_users",
        verbose_name=_("直接权限"),
        blank=True,
    )

    class Meta:
        db_table = "sys_user"
        verbose_name = _("系统用户")
        verbose_name_plural = _("系统用户")

    def __str__(self):
        return self.cn_name or self.username

    def set_password(self, raw_password):
        """加密密码"""
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        """验证密码"""
        return check_password(raw_password, self.password)

    def get_all_roles(self):
        """获取用户所有角色"""
        return self.user_roles.filter(is_active=True).select_related("role")

    def get_all_permissions(self):
        """获取用户所有权限（角色权限 + 直接权限）"""
        permissions = []

        # 获取角色权限
        for user_role in self.get_all_roles():
            role_permissions = user_role.role.get_all_permissions()
            permissions.extend(role_permissions)

        # 获取直接权限
        direct_perms = self.direct_permissions.filter(is_active=True).values(
            "permission_id",
            "permission_code",
            "permission_name",
            "permission_type",
            "data_scope_id",
            "resource__resource_id",
            "resource__resource_name",
            "resource__resource_type",
            "resource__path",
            "resource__table_name",
            "resource__model_class",
            "resource__creator_field",
        )
        # 添加数据范围信息
        for perm in direct_perms:
            if perm["data_scope_id"]:
                try:
                    data_scope = SysDataScope.objects.get(
                        scope_id=perm["data_scope_id"]
                    )
                    perm["data_scope_type"] = data_scope.scope_type
                    perm["data_scope_sql"] = data_scope.custom_sql
                except SysDataScope.DoesNotExist:
                    perm["data_scope_type"] = None
                    perm["data_scope_sql"] = None
            permissions.append(perm)

        # 去重（直接权限优先级高于角色权限）
        seen = set()
        unique_permissions = []
        for perm in permissions:
            key = (perm.get("permission_code"), perm.get("resource__resource_id"))
            if key not in seen:
                seen.add(key)
                unique_permissions.append(perm)

        return unique_permissions

    def has_permission(self, resource_code, required_permission_type):
        """检查用户是否具有某个资源的特定权限"""
        permissions = self.get_all_permissions()
        # 获取用户对该资源的所有权限类型
        user_permission_types = []
        for perm in permissions:
            if perm.get("resource__resource_code") == resource_code:
                user_permission_types.append(perm.get("permission_type", 0))
        if not user_permission_types:
            return False

        # 检查用户是否有任意一个权限类型 >= 要求的权限类型
        max_user_permission = max(user_permission_types)
        return max_user_permission >= required_permission_type

    def get_data_scope_condition(
        self, table_name, permission_type=SysPermission.PERM_READ
    ):
        """
        获取用户对指定数据表的查询条件
        返回SQL WHERE条件字符串
        """
        # 查找用户对该表的所有读取权限
        table_permissions = []
        for perm in self.get_all_permissions():
            if (
                perm.get("resource__resource_type") == "table"
                and perm.get("resource__table_name") == table_name
                and perm.get("permission_type") == permission_type
            ):
                table_permissions.append(perm)

        if not table_permissions:
            return "1=0"  # 无权限，返回永远为假的条件

        # 取最宽松的数据范围（数值越小范围越大）
        best_scope = min(
            table_permissions,
            key=lambda x: x.get("data_scope_type", SysDataScope.SCOPE_SELF),
        )

        scope_type = best_scope.get("data_scope_type")

        if scope_type == SysDataScope.SCOPE_ALL:
            return "1=1"  # 全部数据

        elif scope_type == SysDataScope.SCOPE_SELF:
            creator_field = best_scope.get("resource__creator_field", "created_by")
            return f"{creator_field} = {self.id}"

        # elif scope_type == SysDataScope.SCOPE_CUSTOM:
        #     custom_sql = best_scope.get("data_scope_sql", "")
        #     if custom_sql:
        #         # 替换模板变量
        #         custom_sql = custom_sql.replace("{user_id}", str(self.id))
        #         return custom_sql

        return "1=0"  # 默认无权限

    def filter_queryset_by_permission(
        self, queryset, permission_type=SysPermission.PERM_READ
    ):
        """
        根据用户权限过滤查询集
        """
        model = queryset.model
        table_name = model._meta.db_table

        # 获取数据范围条件
        condition = self.get_data_scope_condition(table_name, permission_type)

        if condition == "1=1":
            return queryset  # 全部数据，无需过滤
        elif condition == "1=0":
            return queryset.none()  # 无权限，返回空查询集
        else:
            # 使用extra方法应用自定义WHERE条件
            return queryset.extra(where=[condition])

    def can_view_all_data(self, table_name):
        """检查用户是否可以查看指定表的全部数据"""
        condition = self.get_data_scope_condition(table_name)
        return condition == "1=1"

    def can_only_view_own_data(self, table_name):
        """检查用户是否只能查看自己的数据"""
        condition = self.get_data_scope_condition(table_name)
        return "=" in condition and str(self.id) in condition


class SysUserRole(BaseModel):
    """用户角色关联"""

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
        verbose_name_plural = _("用户角色关联")
        unique_together = ("user", "role")

    def __str__(self):
        return f"{self.user.cn_name} - {self.role.role_name}"


class SysUserDirectPermission(BaseModel):
    """用户直接权限关联"""

    user = models.ForeignKey(SysUser, on_delete=models.CASCADE, verbose_name=_("用户"))
    permission = models.ForeignKey(
        SysPermission, on_delete=models.CASCADE, verbose_name=_("权限")
    )
    assigned_by = models.ForeignKey(
        SysUser,
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


# 权限检查工具类
class PermissionChecker:
    """权限检查工具类"""

    @staticmethod
    def check_permission(user, resource_code, required_permission_type):
        """
        静态方法检查权限
        """
        return user.has_permission(resource_code, required_permission_type)

    @staticmethod
    def require_permission(resource_code, required_permission_type):
        """
        装饰器：要求用户具有指定权限
        直接在装饰器中指定resource_code和required_permission_type
        """

        def decorator(view_func):
            def wrapper(request, *args, **kwargs):
                if not request.user.is_authenticated:
                    from django.http import HttpResponseForbidden

                    return HttpResponseForbidden("用户未登录")

                if not request.user.has_permission(
                    resource_code, required_permission_type
                ):
                    from django.http import HttpResponseForbidden

                    return HttpResponseForbidden("权限不足")

                return view_func(request, *args, **kwargs)

            return wrapper

        return decorator

    @classmethod
    def require_read_permission(cls, resource_code):
        """快捷方法：要求读取权限"""
        return cls.require_permission(resource_code, SysPermission.PERM_READ)

    @classmethod
    def require_write_permission(cls, resource_code):
        """快捷方法：要求写入权限"""
        return cls.require_permission(resource_code, SysPermission.PERM_WRITE)

    @classmethod
    def require_delete_permission(cls, resource_code):
        """快捷方法：要求删除权限"""
        return cls.require_permission(resource_code, SysPermission.PERM_DELETE)

    @classmethod
    def require_manage_permission(cls, resource_code):
        """快捷方法：要求管理权限"""
        return cls.require_permission(resource_code, SysPermission.PERM_MANAGE)


# 使用示例
def example_usage():
    """使用示例"""

    # 方式1：使用具体权限装饰器
    @PermissionChecker.require_permission("user_management", SysPermission.PERM_WRITE)
    def edit_user_view(request, user_id):
        # 这个视图需要用户管理资源的编辑权限
        pass

    # 方式2：使用快捷方法
    @PermissionChecker.require_read_permission("sales_data")
    def view_sales_data(request):
        # 这个视图需要销售数据资源的读取权限
        pass

    @PermissionChecker.require_write_permission("product_management")
    def edit_product_view(request):
        # 这个视图需要产品管理资源的编辑权限
        pass

    @PermissionChecker.require_manage_permission("system_config")
    def system_config_view(request):
        # 这个视图需要系统配置资源的管理权限
        pass

    # 方式3：在类视图中使用
    from django.utils.decorators import method_decorator
    from django.views import View

    class UserManagementView(View):
        @method_decorator(PermissionChecker.require_write_permission("user_management"))
        def post(self, request):
            # 处理用户编辑请求
            pass

        @method_decorator(PermissionChecker.require_read_permission("user_management"))
        def get(self, request):
            # 获取用户列表
            pass
