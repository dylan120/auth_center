from typing import List

from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import AbstractUser
from django.db import connection, models
from django.utils.translation import gettext_lazy as _

from accounts.models import BaseModel
from accounts.models.perms import SysPermission, SysUserDirectPermission
from accounts.models.scope import SysDataScope


class SysCompany(BaseModel):
    """
    公司主体模型 - 支持多租户/多公司架构
    """

    company_id = models.AutoField(primary_key=True, verbose_name=_("公司ID"))
    company_name = models.CharField(max_length=200, verbose_name=_("公司名称"))
    # 公司状态
    COMPANY_STATUS_ACTIVE = 1  # 正常
    COMPANY_STATUS_DISABLED = 2  # 停用
    COMPANY_STATUS_SUSPENDED = 3  # 暂停

    COMPANY_STATUS_CHOICES = (
        (COMPANY_STATUS_ACTIVE, _("正常")),
        (COMPANY_STATUS_DISABLED, _("停用")),
        (COMPANY_STATUS_SUSPENDED, _("暂停")),
    )

    status = models.IntegerField(
        choices=COMPANY_STATUS_CHOICES,
        default=COMPANY_STATUS_ACTIVE,
        verbose_name=_("公司状态"),
    )

    parent_company = models.ForeignKey(
        "self",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="subsidiaries",
        verbose_name=_("上级公司"),
    )

    class Meta:
        db_table = "sys_company"
        verbose_name = _("公司主体")
        verbose_name_plural = _("公司主体")
        ordering = ["company_name"]

    def __str__(self):
        return str(self.company_name)

    def is_in_company_tree(self, target_company_id):
        """检查公司是否在目标公司的树形结构中"""
        if self.company_id == target_company_id:
            return True

        # 检查是否是目标公司的子公司
        subsidiaries = self.get_all_subsidiaries()
        return any(company.company_id == target_company_id for company in subsidiaries)

    def get_all_subsidiaries(self):
        """获取所有子公司（包括子公司的子公司）"""
        subsidiaries = [self]
        for subsidiary in self.subsidiaries.filter(is_active=True):
            subsidiaries.extend(subsidiary.get_all_subsidiaries())
        return subsidiaries

    def get_all_departments(self):
        """获取公司及所有子公司的部门"""
        all_companies = self.get_all_subsidiaries()
        company_ids = [company.company_id for company in all_companies]
        return SysDepartment.objects.filter(company_id__in=company_ids, is_active=True)

    def get_all_users(self):
        """获取公司及所有子公司的用户"""
        departments = self.get_all_departments()
        dept_ids = [dept.dept_id for dept in departments]
        return SysUser.objects.filter(department_id__in=dept_ids, is_active=True)

    def get_company_roles(self, include_global=True):
        """获取公司所有角色（可选包含全局角色）"""
        roles = self.roles.filter(is_active=True)

        if include_global:
            global_roles = SysRole.objects.filter(company__isnull=True, is_active=True)
            roles = list(roles) + list(global_roles)

        return roles

    def is_active_company(self):
        """检查公司是否处于活跃状态"""
        return self.status == self.COMPANY_STATUS_ACTIVE and self.is_active


class SysDepartment(BaseModel):
    """
    部门模型 - 支持部门层级和角色关联
    """

    dept_id = models.AutoField(primary_key=True, verbose_name=_("部门ID"))
    dept_name = models.CharField(max_length=100, verbose_name=_("部门名称"))
    dept_code = models.CharField(max_length=100, unique=True, verbose_name=_("标识码"))
    parent_dept = models.ForeignKey(
        "self",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="children",
        verbose_name=_("上级部门"),
    )

    company = models.ForeignKey(
        SysCompany,
        on_delete=models.CASCADE,
        related_name="departments",
        verbose_name=_("所属公司"),
    )

    dept_level = models.IntegerField(default=1, verbose_name=_("部门层级"))
    sort_order = models.IntegerField(default=0, verbose_name=_("排序序号"))
    description = models.TextField(blank=True, verbose_name=_("部门描述"))

    class Meta:
        db_table = "sys_department"
        verbose_name = _("部门")
        verbose_name_plural = _("部门")
        ordering = ["company", "dept_level", "sort_order", "dept_name"]
        unique_together = ("company", "dept_code")

    def __str__(self):
        return str(self.dept_name)

    def get_all_sub_departments(self):
        """获取所有下级部门（包括自身）"""
        departments = [self]
        for child in self.children.filter(is_active=True):
            departments.extend(child.get_all_sub_departments())
        return departments

    def get_all_users(self):
        """获取部门及所有下级部门的用户"""

        sub_depts = self.get_all_sub_departments()
        dept_ids = [dept.dept_id for dept in sub_depts]
        return SysUser.objects.filter(department_id__in=dept_ids, is_active=True)

    def get_available_roles(self):
        """获取部门可用的所有角色（包括继承的角色）"""
        # 部门的直接角色
        direct_roles = self.dept_roles.filter(is_active=True)

        # 上级部门的角色（继承）
        inherited_roles = []
        if self.parent_dept:
            inherited_roles = self.parent_dept.get_available_roles()

        # 合并并去重
        all_roles = list(direct_roles) + inherited_roles
        seen = set()
        unique_roles = []
        for role in all_roles:
            if role.role_id not in seen:
                seen.add(role.role_id)
                unique_roles.append(role)

        return unique_roles


class SysRole(BaseModel):
    """
    系统角色模型 - 简化版，通过权限集来管理权限
    """

    role_id = models.AutoField(primary_key=True, verbose_name=_("角色ID"))
    role_name = models.CharField(max_length=50, unique=True, verbose_name=_("角色名称"))
    role_code = models.CharField(max_length=50, unique=True, verbose_name=_("角色编码"))
    description = models.TextField(blank=True, verbose_name=_("角色描述"))

    company = models.ForeignKey(
        SysCompany,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="roles",
        verbose_name=_("所属公司"),
        help_text=_("为空表示全局角色"),
    )

    # 角色关联的权限集（多对多）
    # permission_sets = models.ManyToManyField(
    #     "SysPermissionSet",
    #     through="SysRolePermissionSet",
    #     related_name="roles",
    #     verbose_name=_("权限集"),
    # )

    class Meta:
        db_table = "sys_role"
        verbose_name = _("系统角色")
        verbose_name_plural = _("系统角色")
        ordering = ["role_name", "role_id"]
        # 角色名称和编码在公司内唯一
        unique_together = [("company", "role_name"), ("company", "role_code")]

    def __str__(self):
        company_name = self.company.company_name if self.company else _("全局")
        return f"{company_name} - {self.role_name}"

    # def get_all_perms(self):
    #     """获取角色所有权限（聚合所有权限集的权限）"""
    #     # 使用原生SQL查询提高性能
    #     sql = """
    #     SELECT DISTINCT
    #         p.permission_id, p.permission_code, p.permission_name,
    #         p.permission_type, p.data_scope_id,
    #         r.resource_id, r.resource_name, r.resource_type,
    #         r.resource_code, r.path, r.table_name, r.model_class, r.creator_field,
    #         ds.scope_type as data_scope_type
    #     FROM sys_role role
    #     JOIN sys_role_permission_set rps ON role.role_id = rps.role_id
    #     JOIN sys_permission_set ps ON rps.permission_set_id = ps.set_id
    #     JOIN sys_permission_set_item psi ON ps.set_id = psi.permission_set_id
    #     JOIN sys_permission p ON psi.permission_id = p.permission_id
    #     LEFT JOIN sys_resource r ON p.resource_id = r.resource_id
    #     LEFT JOIN sys_data_scope ds ON p.data_scope_id = ds.scope_id
    #     WHERE role.role_id = %s AND role.is_active = TRUE
    #       AND rps.is_active = TRUE AND ps.is_active = TRUE
    #       AND psi.is_active = TRUE AND p.is_active = TRUE
    #       AND (r.resource_id IS NULL OR r.is_active = TRUE)
    #     """

    #     with connection.cursor() as cursor:
    #         cursor.execute(sql, [self.role_id])
    #         columns = [col[0] for col in cursor.description]
    #         permissions = [dict(zip(columns, row)) for row in cursor.fetchall()]

    #     return permissions

    # 或者使用Django ORM的版本（更推荐，便于维护）
    def get_all_perms_orm(self):
        """使用Django ORM获取角色所有权限"""
        from django.db.models import Q

        # 获取角色关联的所有活跃权限集
        permission_sets = (
            self.sysrolepermissionset_set.filter(
                is_active=True, permission_set__is_active=True
            )
            .select_related("permission_set")
            .prefetch_related("permission_set__permission_items__permission")
        )

        permissions = []

        for role_perm_set in permission_sets:
            permission_set = role_perm_set.permission_set

            # 获取权限集中的所有权限项
            perm_items = permission_set.permission_items.filter(
                is_active=True, permission__is_active=True
            ).select_related("permission")

            for item in perm_items:
                permission = item.permission

                # 构建权限信息
                perm_data = {
                    "permission_id": permission.permission_id,
                    "permission_code": permission.permission_code,
                    "permission_name": permission.permission_name,
                    "permission_type": permission.permission_type,
                    "data_scope_id": permission.data_scope_id,
                    "is_direct": False,  # 角色权限不是直接权限
                }

                # 添加资源信息（如果存在）
                if hasattr(permission, "resource") and permission.resource:
                    resource = permission.resource
                    perm_data.update(
                        {
                            "resource_id": resource.resource_id,
                            "resource_name": resource.resource_name,
                            "resource_code": resource.resource_code,
                            "resource_type": resource.resource_type,
                            "path": getattr(resource, "path", ""),
                            "table_name": getattr(resource, "table_name", ""),
                            "model_class": getattr(resource, "model_class", ""),
                            "creator_field": getattr(
                                resource, "creator_field", "created_by"
                            ),
                        }
                    )

                # 添加数据范围信息（如果存在）
                if permission.data_scope:
                    perm_data["data_scope_type"] = permission.data_scope.scope_type

                permissions.append(perm_data)

        return permissions

    # 推荐使用ORM版本
    def get_all_perms(self):
        """获取角色所有权限 - 使用ORM版本"""
        return self.get_all_perms_orm()


class SysDepartmentRole(BaseModel):
    """
    部门与角色的关联关系
    """

    department = models.ForeignKey(
        SysDepartment,
        on_delete=models.CASCADE,
        related_name="dept_roles",
        verbose_name=_("部门"),
    )
    role = models.ForeignKey(
        SysRole,
        on_delete=models.CASCADE,
        related_name="role_depts",
        verbose_name=_("角色"),
    )
    assigned_by = models.ForeignKey(
        "SysUser", on_delete=models.SET_NULL, null=True, verbose_name=_("分配人")
    )
    # 是否可继承给下级部门
    is_inheritable = models.BooleanField(default=True, verbose_name=_("可继承"))
    # 生效时间
    valid_from = models.DateTimeField(null=True, blank=True, verbose_name=_("生效时间"))
    valid_to = models.DateTimeField(null=True, blank=True, verbose_name=_("失效时间"))

    class Meta:
        db_table = "sys_department_role"
        verbose_name = _("部门角色关联")
        verbose_name_plural = _("部门角色关联")
        unique_together = ("department", "role")

    def clean(self):
        """验证部门和角色属于同一公司"""
        from django.core.exceptions import ValidationError

        if (
            self.department.company
            and self.role.company
            and self.department.company != self.role.company
        ):
            raise ValidationError(_("部门和角色必须属于同一公司"))

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.department.dept_name} - {self.role.role_name}"


class SysUser(AbstractUser):
    """系统用户模型"""

    cn_name = models.CharField(max_length=100, verbose_name=_("显示名称"))

    # department = models.ForeignKey(
    #     SysDepartment,
    #     on_delete=models.SET_NULL,
    #     null=True,
    #     blank=True,
    #     related_name="users",
    #     verbose_name=_("所属部门"),
    # )

    class Meta:
        db_table = "sys_user"
        verbose_name = _("系统用户")
        verbose_name_plural = _("系统用户")

    def __str__(self):
        return str(self.cn_name) or str(self.username)

    def set_password(self, raw_password):
        """加密密码"""
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        """验证密码"""
        return check_password(raw_password, self.password)

    def get_company(self) -> SysCompany:
        """获取用户所属公司"""
        if self.department:
            return self.department.company
        return None

    def get_company_tree(self):
        """获取用户所属公司及所有上级公司"""
        company = self.get_company()
        if not company:
            return []

        companies = [company]
        current = company
        while current.parent_company:
            companies.append(current.parent_company)
            current = current.parent_company

        return companies

    def is_in_company(self, company_pk):
        """检查用户是否属于指定公司"""
        company = self.get_company()
        return company and company.pk == company_pk

    def is_in_company_tree(self, company_pk):
        """检查用户是否属于指定公司或其子公司"""
        companies = self.get_company_tree()
        return any(company.pk == company_pk for company in companies)

    def get_company_roles(self, company_id=None):
        """获取用户在指定公司下的角色"""
        if not company_id:
            user_company = self.get_company()
            company_id = user_company.company_id if user_company else None

        roles = []

        # 个人分配的角色（按公司过滤）
        user_roles = self.user_roles.filter(is_active=True).select_related("role")
        for user_role in user_roles:
            role = user_role.role
            if not company_id or (role.company and role.company.pk == company_id):
                roles.append(role)

        # 部门分配的角色（按公司过滤）
        if self.department:
            dept_roles = self.department.get_available_roles()
            for role in dept_roles:
                if not company_id or (role.company and role.company.pk == company_id):
                    roles.append(role)

        # 去重
        seen = set()
        unique_roles = []
        for role in roles:
            if role.pk not in seen:
                seen.add(role.pk)
                unique_roles.append(role)

        return unique_roles

    def get_all_roles(self, company_pk=None) -> List[SysRole]:
        """获取用户所有角色（个人角色 + 部门角色）"""
        roles: List[SysRole] = []

        # 1. 个人直接分配的角色
        user_roles = self.user_roles.filter(is_active=True).select_related("role")
        roles.extend([ur.role for ur in user_roles])

        # 2. 通过部门分配的角色
        if self.department:
            dept_roles = self.department.get_available_roles()
            roles.extend(dept_roles)

        # 去重
        seen = set()
        unique_roles = []
        for role in roles:
            if role.role_id not in seen:
                seen.add(role.role_id)
                unique_roles.append(role)

        return unique_roles

    def get_accessible_companies(self):
        """获取用户可以访问的公司列表（基于数据权限）"""
        # 这里可以根据用户的数据权限范围返回可访问的公司
        # 例如：超级管理员可以访问所有公司，普通用户只能访问自己所在公司
        if self.has_permission("company_manage", SysPermission.PERM_MANAGE):
            # 有公司管理权限，可以访问所有活跃公司
            return SysCompany.objects.filter(
                status=SysCompany.COMPANY_STATUS_ACTIVE, is_active=True
            )
        else:
            # 普通用户只能访问自己所在公司
            company = self.get_company()
            return [company] if company else []

    # 修改权限检查方法，加入公司范围限制
    def has_permission_within_company(
        self, resource_code, required_permission_type, company_pk=None
    ):
        """
        在指定公司范围内检查权限
        """
        # 如果没有指定公司，使用用户当前公司
        if not company_pk:
            user_company = self.get_company()
            company_pk = user_company.company_pk if user_company else None

        # 检查公司访问权限
        if company_pk and not self.is_in_company_tree(company_pk):
            return False

        # 检查具体权限
        return self.has_permission(resource_code, required_permission_type)

    def has_permission_with_dimensions(
        self, resource_code, required_perm_type, dimension_values=None, company_pk=None
    ):
        """
        检查用户是否拥有指定资源、权限类型和维度组合的权限
        dimension_values: 字典，如{"delivery_method": "feed", "material_source": "delivery"}
        """
        if self.is_superuser:
            return True

        # 获取用户所有权限
        permissions = self.get_all_perms(company_pk)

        for perm in permissions:
            # 检查资源和权限类型匹配
            if perm.get("resource_code") != resource_code:
                continue
            if not self._perm_type_matches(perm, required_perm_type):
                continue

            # 检查维度匹配
            if not self._dimension_matches(perm, dimension_values):
                continue

            return True
        return False

    def _dimension_matches(self, perm, dimension_values):
        """检查权限的维度选项是否匹配请求的维度值"""
        if not dimension_values:
            return True

        # 获取权限关联的维度选项
        perm_dimensions = perm.get("dimension_options", {})

        for dim_code, dim_value in dimension_values.items():
            # 检查该维度是否在权限允许的范围内
            if dim_code not in perm_dimensions:
                return False
            if dim_value not in perm_dimensions[dim_code]:
                return False

        return True

    def get_department_roles(self):
        """获取用户通过部门分配的角色"""
        if not self.department:
            return []
        return self.department.get_available_roles()

    def get_personal_roles(self):
        """获取用户个人分配的角色"""
        return [ur.role for ur in self.user_roles.filter(is_active=True)]

    def has_department_role(self, role_code):
        """检查用户是否通过部门拥有某个角色"""
        if not self.department:
            return False
        dept_roles = self.department.get_available_roles()
        return any(role.role_code == role_code for role in dept_roles)

    def get_all_perms(self, company_pk=None):
        """
        获取用户所有权限（支持按公司过滤）
        修复版本：使用正确的关联查询
        """
        permissions = []

        # 1. 获取角色权限（按公司过滤）
        roles = self.get_all_roles(company_pk)
        for role in roles:
            role_permissions = role.get_all_perms()
            permissions.extend(role_permissions)

        # 2. 获取直接权限（按公司过滤）
        direct_perms = self._get_direct_permissions(company_pk)
        permissions.extend(direct_perms)

        # 去重（基于权限编码和资源ID）
        seen = set()
        unique_permissions = []
        for perm in permissions:
            # 使用权限编码和资源ID作为唯一标识
            key = (perm.get("permission_code"), perm.get("resource_id"))
            if key not in seen:
                seen.add(key)
                unique_permissions.append(perm)

        return unique_permissions

    def _get_direct_permissions(self, company_pk=None):
        """
        获取用户的直接权限
        """
        # 查询直接权限记录
        direct_perms_qs = (
            SysUserDirectPermission.objects.filter(user=self, is_active=True)
            .select_related("permission", "permission__data_scope")
            .prefetch_related("permission__content_type")
        )

        # 按公司过滤
        if company_pk:
            direct_perms_qs = direct_perms_qs.filter(
                models.Q(permission__company__isnull=True)
                | models.Q(permission__company__pk=company_pk)
            )

        direct_permissions = []

        for direct_perm in direct_perms_qs:
            permission = direct_perm.permission

            # 获取关联的资源信息
            resource = None
            if permission.content_type and permission.object_id:
                try:
                    resource = permission.content_type.get_object_for_this_type(
                        pk=permission.object_id
                    )
                except:
                    resource = None

            perm_data = {
                "permission_id": permission.permission_id,
                "permission_code": permission.permission_code,
                "permission_name": permission.permission_name,
                "permission_type": permission.permission_type,
                "data_scope_id": permission.data_scope_id,
                "data_scope_type": permission.data_scope.scope_type
                if permission.data_scope
                else None,
                "is_direct": True,  # 标记为直接权限
                "assigned_by": direct_perm.assigned_by_id,
                "valid_from": direct_perm.valid_from,
                "valid_to": direct_perm.valid_to,
            }

            # 添加资源信息
            if resource:
                perm_data.update(
                    {
                        "resource_id": resource.resource_id,
                        "resource_name": resource.resource_name,
                        "resource_code": resource.resource_code,
                        "resource_type": resource.resource_type,
                        "path": getattr(resource, "path", ""),
                        "table_name": getattr(resource, "table_name", ""),
                        "model_class": getattr(resource, "model_class", ""),
                        "creator_field": getattr(
                            resource, "creator_field", "created_by"
                        ),
                    }
                )

            direct_permissions.append(perm_data)

        return direct_permissions

    def has_permission(self, resource_code, required_permission_type, company_pk=None):
        """
        检查用户是否对指定资源拥有所需权限（字符串类型）

        Args:
            resource_code (str): 资源编码，如 "media"
            required_permission_type (str): 所需权限类型，如 "read"
            company_pk (int, optional): 公司ID

        Returns:
            bool: 是否拥有权限
        """
        if self.is_superuser:
            return True

        permissions = self.get_all_perms(company_pk)
        # 获取用户对该资源的所有权限类型
        for perm in permissions:
            if perm.get("resource_code") != resource_code:
                continue

            user_perm_type = perm.get("permission_type")
            if not user_perm_type:
                continue

            # 1. manage 权限覆盖所有
            if user_perm_type == SysPermission.PERM_MANAGE:
                return True

            # 2. 精确匹配
            if user_perm_type == required_permission_type:
                return True

        return False

    def get_data_scope_condition(
        self, table_name, permission_type=SysPermission.PERM_READ
    ):
        """
        获取用户对指定数据表的查询条件
        """
        # 查找用户对该表的所有相关权限
        table_permissions = []
        for perm in self.get_all_perms():
            if (
                perm.get("table_name") == table_name
                and perm.get("permission_type") == permission_type
            ):
                table_permissions.append(perm)

        if not table_permissions:
            return "1=0"  # 无权限

        # 取最宽松的数据范围
        best_scope = min(
            table_permissions,
            key=lambda x: x.get("data_scope_type", SysDataScope.SCOPE_SELF),
        )

        scope_type = best_scope.get("data_scope_type")
        creator_field = best_scope.get("creator_field", "created_by")

        if scope_type == SysDataScope.SCOPE_SELF:
            return f"{creator_field} = {self.id}"

        elif scope_type == SysDataScope.SCOPE_DEPT:
            if self.department:
                dept_users = self.department.get_all_users()
                user_ids = [str(user.id) for user in dept_users]
                if user_ids:
                    return f"{creator_field} IN ({','.join(user_ids)})"
            return "1=0"

        elif scope_type == SysDataScope.SCOPE_COMPANY:
            company = self.get_company()
            if not company:
                return "1=0"
            subsidiaries = company.get_all_subsidiaries()
            company_ids = [str(c.company_id) for c in subsidiaries]
            return f"company_id IN ({','.join(company_ids)})"

        return "1=0"

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

    def get_effective_permissions(self, resource_code, company_pk=None):
        """
        获取用户对指定资源的所有有效权限类型
        """
        permissions = self.get_all_perms(company_pk)
        effective_perms = set()

        for perm in permissions:
            if perm.get("resource_code") == resource_code:
                perm_type = perm.get("permission_type")
                if perm_type:
                    effective_perms.add(perm_type)
                    # 如果有管理权限，添加所有权限类型
                    if perm_type == SysPermission.PERM_MANAGE:
                        return set(
                            [choice[0] for choice in SysPermission.PERM_TYPE_CHOICES]
                        )

        return effective_perms


class SysUserDepartment(BaseModel):
    """
    部门与用户的关联关系
    """

    department = models.ForeignKey(
        SysDepartment,
        on_delete=models.CASCADE,
        related_name="dept_users",
        verbose_name=_("部门"),
    )

    user = models.ForeignKey(
        SysUser,
        on_delete=models.CASCADE,
        related_name="user_depts",
        verbose_name=_("用户"),
    )

    class Meta:
        db_table = "sys_department_user"
        verbose_name = _("部门用户关联")
        verbose_name_plural = _("部门用户关联")
        unique_together = ("department", "user")


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

    def clean(self):
        """验证用户和角色公司一致性"""
        from django.core.exceptions import ValidationError

        user_company = self.user.get_company()
        role_company = self.role.company

        # 如果角色有特定公司，用户必须属于该公司或其子公司
        if role_company and user_company:
            if not user_company.is_in_company_tree(role_company.company_id):
                raise ValidationError(_("用户必须属于角色所在公司或其子公司"))

        # 如果用户有特定公司，全局角色可以分配，但公司特定角色必须匹配
        elif user_company and role_company:
            if user_company != role_company:
                raise ValidationError(_("用户和角色必须属于同一公司"))

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.cn_name} - {self.role.role_name}"
