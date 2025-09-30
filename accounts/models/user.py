from datetime import datetime
from typing import List

# from django.contrib.auth.hashers import check_password, make_password
# from django.contrib.auth.models import AbstractBaseUser
from django.core.exceptions import ValidationError
from django.db import connection, models
from django.utils.translation import gettext_lazy as _

from accounts.manager.sys_user_manager import SysUserManager
from accounts.models import BaseModel
from accounts.models.perms import (
    SysPermission,
    SysRolePermissionSet,
    SysUserDirectPermission,
)
from accounts.models.resources import SysTableResource
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
        for subsidiary in self.subsidiaries.all():
            subsidiaries.extend(subsidiary.get_all_subsidiaries())
        return subsidiaries

    def get_all_departments(self):
        """获取公司及所有子公司的部门"""
        all_companies = self.get_all_subsidiaries()
        company_ids = [company.company_id for company in all_companies]
        return SysDepartment.objects.filter(company_id__in=company_ids)

    def get_all_users(self):
        """获取公司及所有子公司的用户"""
        departments = self.get_all_departments()
        dept_ids = [dept.dept_id for dept in departments]
        return SysUser.objects.filter(department_id__in=dept_ids)

    def is_active_company(self):
        """检查公司是否处于活跃状态"""
        return self.status == self.COMPANY_STATUS_ACTIVE


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
        for child in self.children.all():
            departments.extend(child.get_all_sub_departments())
        return departments

    def get_all_users(self):
        """获取部门及所有下级部门的用户"""
        sub_depts = self.get_all_sub_departments()
        dept_ids = [dept.dept_id for dept in sub_depts]
        return SysUser.objects.filter(department_id__in=dept_ids)

    def get_available_roles(self, company_pk=None):
        """获取部门可用的所有角色（包括继承的角色）"""
        # 部门的直接角色
        direct_roles = self.dept_roles.all()

        # 按公司过滤
        if company_pk:
            direct_roles = direct_roles.filter(
                models.Q(role__company__isnull=True)
                | models.Q(role__company__pk=company_pk)
            )

        direct_role_objs = [dr.role for dr in direct_roles]

        # 上级部门的角色（继承）
        inherited_roles = []
        if self.parent_dept:
            inherited_roles = self.parent_dept.get_available_roles(company_pk)

        # 合并并去重
        all_roles = direct_role_objs + inherited_roles
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
    role_name = models.CharField(max_length=50, verbose_name=_("角色名称"))
    role_code = models.CharField(max_length=50, verbose_name=_("角色编码"))
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

    def get_all_perms_orm(self, company_pk=None):
        """获取角色所有权限 - ORM版本"""
        # 获取角色关联的所有权限集
        permission_sets = self.permission_bindings.all().select_related(
            "permission_set"
        )

        # 按公司过滤
        if company_pk:
            permission_sets = permission_sets.filter(
                models.Q(permission_set__company__isnull=True)
                | models.Q(permission_set__company__pk=company_pk)
            )

        permissions = []

        for role_perm_set in permission_sets:
            permission_set = role_perm_set.permission_set

            # 获取权限集中的所有权限项
            perm_items = permission_set.permission_items.all().select_related(
                "permission"
            )

            for item in perm_items:
                permission = item.permission

                # 按公司过滤权限
                if (
                    company_pk
                    and permission.company
                    and permission.company.pk != company_pk
                ):
                    continue

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

    def get_all_perms(self, company_pk=None):
        """获取角色所有权限 - 使用ORM版本"""
        return self.get_all_perms_orm(company_pk)


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


class SysUser(BaseModel):
    """系统用户模型"""

    USER_STATUS_NORMAL = 0  # 正常
    USER_STATUS_LOCAK = 1  # 锁定
    USER_STATUS_DELETE = 2  # 删除
    USER_STATUS_PENDING = 3  # 待分配

    USER_STATUS_CHOICES = (
        (USER_STATUS_NORMAL, _("正常")),
        (USER_STATUS_LOCAK, _("锁定")),
        (USER_STATUS_DELETE, _("删除")),
        (USER_STATUS_PENDING, _("待分配")),
    )

    phone = models.CharField("手机号", max_length=11, unique=True)
    email = models.EmailField("邮箱", blank=True, null=True)
    full_name = models.CharField("姓名", max_length=150, blank=True)
    is_active = models.BooleanField("激活状态", default=True)
    is_super = models.BooleanField("管理员", default=False)
    date_joined = models.DateTimeField("注册时间", auto_now_add=True)
    last_ip = models.CharField("最后登录ip", max_length=20)
    last_time = models.DateTimeField("最后登录时间", default=datetime.now)
    login_count = models.IntegerField("登录次数", default=0)
    login_err_count = models.IntegerField("登录错误次数", default=0)
    lock_time = models.DateTimeField("锁定时间", null=True, blank=True)
    login_err_time = models.DateTimeField("登录错误时间", null=True, blank=True)
    is_white = models.IntegerField("白名单", default=0)  # 0否， 1:是
    reason = models.CharField("申请理由", max_length=255)
    status = models.IntegerField("状态", default=0, choices=USER_STATUS_CHOICES)

    # 设置 phone 为登录字段
    USERNAME_FIELD = "phone"
    REQUIRED_FIELDS = ["email"]  # 创建 superuser 时需要输入的字段

    objects = SysUserManager()

    class Meta:
        db_table = "sys_user"
        verbose_name = _("系统用户")
        verbose_name_plural = _("系统用户")

    def __str__(self):
        return str(self.cn_name) or str(self.username)

    # def set_password(self, raw_password):
    #     """加密密码"""
    #     self.password = make_password(raw_password)

    # def check_password(self, raw_password):
    #     """验证密码"""
    #     return check_password(raw_password, self.password)

    def get_company(self, company_pk) -> SysCompany:
        """获取用户在指定公司的所属公司"""
        user_dept = (
            self.user_depts.filter(department__company__pk=company_pk)
            .select_related("department", "department__company")
            .first()
        )
        if user_dept and user_dept.department:
            return user_dept.department.company
        return None

    def get_company_tree(self, company_pk):
        """获取用户在指定公司的公司树"""
        company = self.get_company(company_pk)
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
        company = self.get_company(company_pk)
        return company and company.pk == company_pk

    def is_in_company_tree(self, company_pk):
        """检查用户是否属于指定公司或其子公司"""
        companies = self.get_company_tree(company_pk)
        return any(company.pk == company_pk for company in companies)

    def get_company_roles(self, company_pk) -> List[SysRole]:
        """获取用户在指定公司下的角色"""
        if not company_pk:
            raise ValueError("company_pk 参数是必需的")

        roles = []

        # 个人分配的角色（按公司过滤）
        user_roles = self.user_roles.all().select_related("role", "role__company")

        for user_role in user_roles:
            role = user_role.role
            # 只包含全局角色或指定公司的角色
            if role.company is None or role.company.pk == company_pk:
                roles.append(role)

        # 部门分配的角色（按公司过滤）
        user_depts = self.user_depts.filter(
            department__company__pk=company_pk
        ).select_related("department")

        for user_dept in user_depts:
            dept_roles = user_dept.department.get_available_roles(company_pk)
            roles.extend(dept_roles)

        # 去重
        seen = set()
        unique_roles = []
        for role in roles:
            if role.pk not in seen:
                seen.add(role.pk)
                unique_roles.append(role)

        return unique_roles

    def has_permission_within_company(
        self, resource_code, required_permission_type, company_pk
    ):
        """
        在指定公司范围内检查权限
        """
        if not company_pk:
            raise ValueError("company_pk 参数是必需的")

        # 检查公司访问权限
        if not self.is_in_company_tree(company_pk):
            return False

        # 检查具体权限
        return self.has_permission(resource_code, required_permission_type, company_pk)

    def get_department_roles(self, company_pk):
        """获取用户在指定公司通过部门分配的角色"""
        if not company_pk:
            raise ValueError("company_pk 参数是必需的")

        user_depts = self.user_depts.filter(
            department__company__pk=company_pk
        ).select_related("department")

        all_roles = []
        for user_dept in user_depts:
            dept_roles = user_dept.department.get_available_roles(company_pk)
            all_roles.extend(dept_roles)

        return all_roles

    def get_personal_roles(self, company_pk=None):
        """获取用户个人分配的角色（可选按公司过滤）"""
        user_roles_qs = self.user_roles.all().select_related("role", "role__company")

        # 按公司过滤
        if company_pk:
            user_roles_qs = user_roles_qs.filter(
                models.Q(role__company__isnull=True)
                | models.Q(role__company__pk=company_pk)
            )

        return [ur.role for ur in user_roles_qs]

    def has_department_role(self, role_code, company_pk):
        """检查用户在指定公司是否通过部门拥有某个角色"""
        if not company_pk:
            raise ValueError("company_pk 参数是必需的")

        dept_roles = self.get_department_roles(company_pk)
        return any(role.role_code == role_code for role in dept_roles)

    def get_all_roles(self, company_pk) -> List[SysRole]:
        """获取用户在指定公司的所有角色（个人角色 + 部门角色）"""
        if not company_pk:
            raise ValueError("company_pk 参数是必需的")

        roles: List[SysRole] = []

        # 1. 个人直接分配的角色
        personal_roles = self.get_personal_roles(company_pk)
        roles.extend(personal_roles)

        # 2. 通过部门分配的角色
        dept_roles = self.get_department_roles(company_pk)
        roles.extend(dept_roles)

        # 去重
        seen = set()
        unique_roles = []
        for role in roles:
            if role.role_id not in seen:
                seen.add(role.role_id)
                unique_roles.append(role)

        return unique_roles

    def get_all_perms(self, company_pk):
        """
        获取用户在指定公司的所有权限
        """
        if not company_pk:
            raise ValueError("company_pk 参数是必需的")

        permissions = []

        # 1. 获取角色权限（按公司过滤）
        roles = self.get_company_roles(company_pk)
        for role in roles:
            role_permissions = role.get_all_perms(company_pk)
            permissions.extend(role_permissions)

        # 2. 获取直接权限（按公司过滤）
        direct_perms = self._get_direct_permissions(company_pk)
        permissions.extend(direct_perms)

        # 去重（基于权限编码和资源ID）
        seen = set()
        unique_permissions = []
        for perm in permissions:
            key = (perm.get("permission_code"), perm.get("resource_id"))
            if key not in seen:
                seen.add(key)
                unique_permissions.append(perm)

        return unique_permissions

    def _get_direct_permissions(self, company_pk):
        """
        获取用户在指定公司的直接权限
        """
        # 查询直接权限记录
        direct_perms_qs = (
            SysUserDirectPermission.objects.filter(user=self)
            .select_related("permission", "permission__data_scope")
            .prefetch_related("permission__content_type")
        )

        # 按公司过滤
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

    def has_permission(self, resource_code, required_permission_type, company_pk):
        """
        检查用户在指定公司是否对指定资源拥有所需权限
        """
        if not company_pk:
            raise ValueError("company_pk 参数是必需的")

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
        self, table_name, company_pk, permission_type=SysPermission.PERM_READ
    ):
        """
        获取用户在指定公司对指定数据表的查询条件
        """
        if not company_pk:
            raise ValueError("company_pk 参数是必需的")

        # 查找用户对该表的所有相关权限
        table_permissions = []
        for perm in self.get_all_perms(company_pk):
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
            # 获取用户在指定公司的部门
            user_depts = self.user_depts.filter(
                department__company__pk=company_pk
            ).select_related("department")

            dept_users = []
            for user_dept in user_depts:
                dept_users.extend(user_dept.department.get_all_users())

            user_ids = [str(user.id) for user in dept_users]
            if user_ids:
                return f"{creator_field} IN ({','.join(user_ids)})"
            return "1=0"

        elif scope_type == SysDataScope.SCOPE_COMPANY:
            company = self.get_company(company_pk)
            if not company:
                return "1=0"
            subsidiaries = company.get_all_subsidiaries()
            company_ids = [str(c.company_id) for c in subsidiaries]
            return f"company_id IN ({','.join(company_ids)})"

        return "1=0"

    def filter_queryset_by_permission(
        self, queryset, company_pk, permission_type=SysPermission.PERM_READ
    ):
        """
        根据用户在指定公司的权限过滤查询集
        """
        if not company_pk:
            raise ValueError("company_pk 参数是必需的")

        model = queryset.model
        table_name = model._meta.db_table

        # 获取数据范围条件
        condition = self.get_data_scope_condition(
            table_name, company_pk, permission_type
        )

        if condition == "1=1":
            return queryset  # 全部数据，无需过滤
        elif condition == "1=0":
            return queryset.none()  # 无权限，返回空查询集
        else:
            # 使用extra方法应用自定义WHERE条件
            return queryset.extra(where=[condition])

    def can_view_all_data(self, table_name, company_pk):
        """检查用户在指定公司是否可以查看指定表的全部数据"""
        condition = self.get_data_scope_condition(table_name, company_pk)
        return condition == "1=1"

    def can_only_view_own_data(self, table_name, company_pk):
        """检查用户在指定公司是否只能查看自己的数据"""
        condition = self.get_data_scope_condition(table_name, company_pk)
        return "=" in condition and str(self.id) in condition

    def get_effective_permissions(self, resource_code, company_pk):
        """
        获取用户在指定公司对指定资源的所有有效权限类型
        """
        if not company_pk:
            raise ValueError("company_pk 参数是必需的")

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

    def get_all_perms_with_dimensions(self, company_pk):
        """获取用户在指定公司的所有权限（包含维度信息）"""
        if not company_pk:
            raise ValueError("company_pk 参数是必需的")

        permissions = []

        # 1. 获取角色权限（按公司过滤）
        roles = self.get_company_roles(company_pk)
        for role in roles:
            role_permissions = self._get_role_perms_with_dimensions(role, company_pk)
            permissions.extend(role_permissions)

        # 2. 获取直接权限（按公司过滤）
        direct_perms = self._get_direct_permissions_with_dimensions(company_pk)
        permissions.extend(direct_perms)

        # 去重（基于权限编码和资源ID）
        seen = set()
        unique_permissions = []
        for perm in permissions:
            key = (perm.get("permission_code"), perm.get("resource_id"))
            if key not in seen:
                seen.add(key)
                unique_permissions.append(perm)

        return unique_permissions

    def _get_role_perms_with_dimensions(self, role, company_pk):
        """获取角色权限（包含维度信息）"""
        permissions = []

        # 获取角色关联的权限集
        role_permission_sets = SysRolePermissionSet.objects.filter(
            role=role
        ).select_related("permission_set")

        # 按公司过滤
        role_permission_sets = role_permission_sets.filter(
            models.Q(permission_set__company__isnull=True)
            | models.Q(permission_set__company__pk=company_pk)
        )

        for role_perm_set in role_permission_sets:
            permission_set = role_perm_set.permission_set

            # 获取权限集中的所有权限项
            perm_items = permission_set.permission_items.all().select_related(
                "permission"
            )

            for item in perm_items:
                permission = item.permission
                # 按公司过滤权限
                if (
                    company_pk
                    and permission.company
                    and permission.company.pk != company_pk
                ):
                    continue

                perm_data = self._build_permission_data(permission)
                perm_data["is_direct"] = False
                perm_data["permission_set_item"] = item
                permissions.append(perm_data)

        return permissions

    def _get_direct_permissions_with_dimensions(self, company_pk):
        """获取用户在指定公司的直接权限（包含维度信息）"""
        direct_perms_qs = (
            SysUserDirectPermission.objects.filter(user=self)
            .select_related("permission", "permission__data_scope")
            .prefetch_related("permission__content_type")
        )

        # 按公司过滤
        direct_perms_qs = direct_perms_qs.filter(
            models.Q(permission__company__isnull=True)
            | models.Q(permission__company__pk=company_pk)
        )

        direct_permissions = []
        for direct_perm in direct_perms_qs:
            permission = direct_perm.permission
            perm_data = self._build_permission_data(permission)
            perm_data["is_direct"] = True
            perm_data["user_direct_permission"] = direct_perm
            direct_permissions.append(perm_data)

        return direct_permissions

    def has_permission_with_dimensions(
        self,
        resource_code,
        required_permission_type,
        company_pk,
        dimension_filters=None,
    ):
        """
        检查用户在指定公司是否对指定资源拥有所需权限（包含维度检查）
        """
        if not company_pk:
            raise ValueError("company_pk 参数是必需的")

        if self.is_superuser:
            return True

        permissions = self.get_all_perms_with_dimensions(company_pk)

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
                # 检查维度权限
                if dimension_filters and self._check_dimension_permission(
                    perm, dimension_filters
                ):
                    return True
                elif not dimension_filters:
                    return True

        return False

    def _build_permission_data(self, permission):
        """构建权限数据"""
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
                    "creator_field": getattr(resource, "creator_field", "created_by"),
                }
            )

        return perm_data

    def _check_dimension_permission(self, permission_data, dimension_filters):
        """检查维度权限"""
        if permission_data.get("is_direct"):
            user_direct_perm = permission_data.get("user_direct_permission")
            if user_direct_perm:
                return self._check_direct_permission_dimensions(
                    user_direct_perm, dimension_filters
                )
        else:
            permission_set_item = permission_data.get("permission_set_item")
            if permission_set_item:
                return self._check_permission_set_item_dimensions(
                    permission_set_item, dimension_filters
                )

        return False

    def _check_direct_permission_dimensions(self, user_direct_perm, dimension_filters):
        """检查直接权限的维度"""
        dimension_options = user_direct_perm.get_dimension_options()
        return self._check_dimension_filters(dimension_options, dimension_filters)

    def _check_permission_set_item_dimensions(
        self, permission_set_item, dimension_filters
    ):
        """检查权限集项的维度"""
        dimension_options = permission_set_item.get_dimension_options()
        return self._check_dimension_filters(dimension_options, dimension_filters)

    def _check_dimension_filters(self, dimension_options, dimension_filters):
        """检查维度过滤器"""
        if not dimension_filters:
            return True

        for dim_code, expected_value in dimension_filters.items():
            has_matching_option = False
            for dim_option_rel in dimension_options:
                if (
                    dim_option_rel.dimension_option.dimension.dimension_code == dim_code
                    and dim_option_rel.dimension_option.option_value == expected_value
                ):
                    has_matching_option = True
                    break
            if not has_matching_option:
                return False
        return True


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

    def __str__(self):
        return f"{self.user.cn_name} - {self.role.role_name}"
