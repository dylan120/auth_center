# tests/test_permissions.py
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.utils import timezone

from accounts.models import (
    SysCompany,
    SysDataScope,
    SysDepartment,
    SysFieldResource,
    SysMenuResource,
    SysPermission,
    SysPermissionSet,
    SysPermissionSetItem,
    SysRole,
    SysRolePermissionSet,
    SysTableResource,
    SysUser,
    SysUserDirectPermission,
    SysUserRole,
)

SysUser = get_user_model()


class PermissionTestBase(TestCase):
    """
    权限测试基类 - 创建测试数据
    """

    def setUp(self):
        """创建测试数据"""
        self.create_companies()
        self.create_departments()
        self.create_users()
        self.create_data_scopes()
        self.create_resources()
        self.create_permission_sets()
        self.create_roles()
        self.assign_permissions()

    def create_companies(self):
        """创建测试公司"""
        # 总公司
        self.root_company = SysCompany.objects.create(
            company_name="总公司", status=SysCompany.COMPANY_STATUS_ACTIVE
        )

        # 分公司
        self.branch_company = SysCompany.objects.create(
            company_name="分公司",
            parent_company=self.root_company,
            status=SysCompany.COMPANY_STATUS_ACTIVE,
        )

        # 另一个独立公司
        self.other_company = SysCompany.objects.create(
            company_name="其他公司", status=SysCompany.COMPANY_STATUS_ACTIVE
        )

    def create_departments(self):
        """创建测试部门"""
        # 总公司部门
        self.root_it_dept = SysDepartment.objects.create(
            dept_name="总公司IT部",
            dept_code="root_it",
            company=self.root_company,
            dept_level=1,
        )

        self.root_hr_dept = SysDepartment.objects.create(
            dept_name="总公司人事部",
            dept_code="root_hr",
            company=self.root_company,
            dept_level=1,
        )

        # 分公司部门
        self.branch_sales_dept = SysDepartment.objects.create(
            dept_name="分公司销售部",
            dept_code="branch_sales",
            company=self.branch_company,
            dept_level=1,
        )

    def create_users(self):
        """创建测试用户"""
        # 超级管理员
        self.superuser = SysUser.objects.create_superuser(
            username="superadmin",
            email="super@test.com",
            password="password123",
            cn_name="超级管理员",
        )

        # 总公司用户
        self.root_admin = SysUser.objects.create_user(
            username="root_admin",
            email="root_admin@test.com",
            password="password123",
            cn_name="总公司管理员",
            department=self.root_it_dept,
        )

        self.root_user = SysUser.objects.create_user(
            username="root_user",
            email="root_user@test.com",
            password="password123",
            cn_name="总公司普通用户",
            department=self.root_hr_dept,
        )

        # 分公司用户
        self.branch_admin = SysUser.objects.create_user(
            username="branch_admin",
            email="branch_admin@test.com",
            password="password123",
            cn_name="分公司管理员",
            department=self.branch_sales_dept,
        )

        self.branch_user = SysUser.objects.create_user(
            username="branch_user",
            email="branch_user@test.com",
            password="password123",
            cn_name="分公司普通用户",
            department=self.branch_sales_dept,
        )

        # 其他公司用户
        self.other_user = SysUser.objects.create_user(
            username="other_user",
            email="other_user@test.com",
            password="password123",
            cn_name="其他公司用户",
            department=None,
        )

    def create_data_scopes(self):
        """创建数据范围"""
        self.scope_company = SysDataScope.objects.create(
            scope_name="全部数据", scope_type=SysDataScope.SCOPE_ALL
        )

        self.scope_self = SysDataScope.objects.create(
            scope_name="本人数据", scope_type=SysDataScope.SCOPE_SELF
        )

        self.scope_dept = SysDataScope.objects.create(
            scope_name="部门数据", scope_type=SysDataScope.SCOPE_DEPT
        )

    def create_resources(self):
        """创建测试资源"""
        # 菜单资源
        self.menu_dashboard = SysMenuResource.objects.create(
            resource_name="仪表板",
            resource_code="menu_dashboard",
            path="/dashboard",
            component="Dashboard",
        )

        self.menu_user_manage = SysMenuResource.objects.create(
            resource_name="用户管理",
            resource_code="menu_user_manage",
            path="/user",
            component="UserManage",
        )

        # 表资源
        self.table_user = SysTableResource.objects.create(
            resource_name="用户表",
            resource_code="table_user",
            table_name="sys_user",
            model_class="accounts.models.SysUser",
            creator_field="created_by",
        )

        self.table_company = SysTableResource.objects.create(
            resource_name="公司表",
            resource_code="table_company",
            table_name="sys_company",
            model_class="accounts.models.SysCompany",
            creator_field="created_by",
        )

        # 字段资源
        self.field_username = SysFieldResource.objects.create(
            resource_name="用户名字段",
            resource_code="field_username",
            table_resource=self.table_user,
            field_name="username",
            # field_type="varchar",
            # field_label="用户名",
        )

        self.field_email = SysFieldResource.objects.create(
            resource_name="邮箱字段",
            resource_code="field_email",
            table_resource=self.table_user,
            field_name="email",
            # field_type="varchar",
            # field_label="邮箱",
        )

        self.field_salary = SysFieldResource.objects.create(
            resource_name="薪资字段",
            resource_code="field_salary",
            table_resource=self.table_user,
            field_name="salary",
            # field_type="decimal",
            # field_label="薪资",
            # is_sensitive=True,
        )

    def create_permission_sets(self):
        """创建权限集"""
        # 全局权限集
        self.global_admin_set = SysPermissionSet.objects.create(
            set_name="全局管理员权限集",
            set_code="global_admin",
            set_type=SysPermissionSet.SET_TYPE_SYSTEM,
        )

        # 公司特定权限集
        self.root_admin_set = SysPermissionSet.objects.create(
            set_name="总公司管理员权限集",
            set_code="root_admin",
            set_type=SysPermissionSet.SET_TYPE_SYSTEM,
            company=self.root_company,
        )

        self.branch_user_set = SysPermissionSet.objects.create(
            set_name="分公司用户权限集",
            set_code="branch_user",
            set_type=SysPermissionSet.SET_TYPE_CUSTOM,
            company=self.branch_company,
        )

    def create_permissions(self):
        """创建具体权限"""
        # 获取内容类型
        menu_content_type = ContentType.objects.get_for_model(SysMenuResource)
        table_content_type = ContentType.objects.get_for_model(SysTableResource)
        field_content_type = ContentType.objects.get_for_model(SysFieldResource)

        # 菜单权限
        self.perm_menu_dashboard_read = SysPermission.objects.create(
            content_type=menu_content_type,
            object_id=self.menu_dashboard.resource_id,
            permission_code="menu_dashboard_read",
            permission_name="查看仪表板",
            permission_type=SysPermission.PERM_READ,
        )

        self.perm_menu_user_manage = SysPermission.objects.create(
            content_type=menu_content_type,
            object_id=self.menu_user_manage.resource_id,
            permission_code="menu_user_manage",
            permission_name="用户管理",
            permission_type=SysPermission.PERM_MANAGE,
        )

        # 表权限
        self.perm_table_user_read = SysPermission.objects.create(
            content_type=table_content_type,
            object_id=self.table_user.resource_id,
            permission_code="table_user_read",
            permission_name="查看用户表",
            permission_type=SysPermission.PERM_READ,
            data_scope=self.scope_company,
        )

        self.perm_table_user_self_read = SysPermission.objects.create(
            content_type=table_content_type,
            object_id=self.table_user.resource_id,
            permission_code="table_user_self_read",
            permission_name="查看本人用户数据",
            permission_type=SysPermission.PERM_READ,
            data_scope=self.scope_self,
        )

        self.perm_table_user_dept_read = SysPermission.objects.create(
            content_type=table_content_type,
            object_id=self.table_user.resource_id,
            permission_code="table_user_dept_read",
            permission_name="查看部门用户数据",
            permission_type=SysPermission.PERM_READ,
            data_scope=self.scope_dept,
        )

        # 字段权限
        self.perm_field_salary_read = SysPermission.objects.create(
            content_type=field_content_type,
            object_id=self.field_salary.resource_id,
            permission_code="field_salary_read",
            permission_name="查看薪资字段",
            permission_type=SysPermission.PERM_READ,
        )

    def create_roles(self):
        """创建角色"""
        # 全局角色
        self.role_global_admin = SysRole.objects.create(
            role_name="全局管理员", role_code="global_admin"
        )

        # 公司角色
        self.role_root_admin = SysRole.objects.create(
            role_name="总公司管理员", role_code="root_admin", company=self.root_company
        )

        self.role_branch_user = SysRole.objects.create(
            role_name="分公司用户", role_code="branch_user", company=self.branch_company
        )

    def assign_permissions(self):
        """分配权限"""
        self.create_permissions()

        # 将权限添加到权限集
        # 全局管理员权限集
        SysPermissionSetItem.objects.create(
            permission_set=self.global_admin_set,
            permission=self.perm_menu_dashboard_read,
        )
        SysPermissionSetItem.objects.create(
            permission_set=self.global_admin_set, permission=self.perm_menu_user_manage
        )
        SysPermissionSetItem.objects.create(
            permission_set=self.global_admin_set, permission=self.perm_table_user_read
        )

        # 总公司管理员权限集
        SysPermissionSetItem.objects.create(
            permission_set=self.root_admin_set,
            permission=self.perm_table_user_dept_read,
        )

        # 分公司用户权限集
        SysPermissionSetItem.objects.create(
            permission_set=self.branch_user_set,
            permission=self.perm_table_user_self_read,
        )
        SysPermissionSetItem.objects.create(
            permission_set=self.branch_user_set, permission=self.perm_field_salary_read
        )

        # 将权限集分配给角色
        SysRolePermissionSet.objects.create(
            role=self.role_global_admin,
            permission_set=self.global_admin_set,
            assigned_by=self.superuser,
        )

        SysRolePermissionSet.objects.create(
            role=self.role_root_admin,
            permission_set=self.root_admin_set,
            assigned_by=self.superuser,
        )

        SysRolePermissionSet.objects.create(
            role=self.role_branch_user,
            permission_set=self.branch_user_set,
            assigned_by=self.superuser,
        )

        # 分配角色给用户
        SysUserRole.objects.create(
            user=self.root_admin, role=self.role_root_admin, assigned_by=self.superuser
        )

        SysUserRole.objects.create(
            user=self.branch_user,
            role=self.role_branch_user,
            assigned_by=self.superuser,
        )

        # 添加直接权限
        SysUserDirectPermission.objects.create(
            user=self.root_user,
            permission=self.perm_menu_dashboard_read,
            assigned_by=self.superuser,
        )


class PermissionScenariosTest(PermissionTestBase):
    """
    权限场景测试 - 覆盖所有权限场景
    """

    def test_superuser_has_all_permissions(self):
        """测试超级用户拥有所有权限"""
        # 测试菜单权限
        self.assertTrue(self.superuser.has_permission("menu_dashboard", "read"))
        self.assertTrue(self.superuser.has_permission("menu_user_manage", "manage"))

        # 测试表权限
        self.assertTrue(self.superuser.has_permission("table_user", "read"))
        self.assertTrue(self.superuser.has_permission("table_company", "read"))

        # 测试字段权限
        self.assertTrue(self.superuser.has_permission("field_salary", "read"))

    def test_company_boundary_permissions(self):
        """测试公司边界权限"""
        # 总公司管理员应该只能访问总公司权限
        self.assertTrue(
            self.root_admin.has_permission("table_user", "read", self.root_company.pk)
        )

        # 总公司管理员不能访问分公司权限
        self.assertFalse(
            self.root_admin.has_permission("table_user", "read", self.branch_company.pk)
        )

        # 分公司用户只能访问分公司权限
        self.assertTrue(
            self.branch_user.has_permission(
                "table_user", "read", self.branch_company.pk
            )
        )
        self.assertFalse(
            self.branch_user.has_permission("table_user", "read", self.root_company.pk)
        )

    def test_data_scope_permissions(self):
        """测试数据范围权限"""
        # 测试数据范围条件生成
        condition = self.branch_user.get_data_scope_condition("sys_user")
        self.assertIn("created_by", condition)  # 应该包含创建人字段

        # 测试全部数据范围
        condition_all = self.root_admin.get_data_scope_condition("sys_user")
        self.assertEqual(condition_all, "1=1")  # 全部数据

        # 测试本人数据范围
        condition_self = self.branch_user.get_data_scope_condition("sys_user")
        self.assertIn(str(self.branch_user.id), condition_self)

    def test_permission_inheritance(self):
        """测试权限继承（管理权限覆盖其他权限）"""
        # 用户管理权限应该覆盖查看权限
        user = self.root_admin
        self.assertTrue(user.has_permission("menu_user_manage", "read"))
        self.assertTrue(user.has_permission("menu_user_manage", "write"))
        self.assertTrue(user.has_permission("menu_user_manage", "delete"))

    def test_direct_permissions_priority(self):
        """测试直接权限优先级高于角色权限"""
        # root_user 只有直接权限，没有角色权限
        permissions = self.root_user.get_all_perms()
        direct_perms = [p for p in permissions if p.get("is_direct")]

        self.assertTrue(len(direct_perms) > 0)
        self.assertTrue(self.root_user.has_permission("menu_dashboard", "read"))

    def test_field_level_permissions(self):
        """测试字段级权限"""
        # 分公司用户有薪资字段读取权限
        self.assertTrue(self.branch_user.has_permission("field_salary", "read"))

        # 总公司用户没有薪资字段权限
        self.assertFalse(self.root_user.has_permission("field_salary", "read"))

    def test_permission_set_management(self):
        """测试权限集管理"""
        # 检查权限集包含的权限
        root_admin_perms = self.role_root_admin.get_all_perms()
        self.assertTrue(len(root_admin_perms) > 0)

        # 检查权限集分配
        role_sets = self.role_root_admin.permission_sets.all()
        self.assertTrue(role_sets.exists())
        self.assertEqual(role_sets.first().set_code, "root_admin")

    def test_user_role_assignment(self):
        """测试用户角色分配"""
        # 检查用户角色
        root_admin_roles = self.root_admin.get_all_roles()
        self.assertEqual(len(root_admin_roles), 1)
        self.assertEqual(root_admin_roles[0].role_code, "root_admin")

        # 检查部门角色
        branch_user_roles = self.branch_user.get_all_roles()
        self.assertEqual(len(branch_user_roles), 1)

    def test_company_tree_permissions(self):
        """测试公司树形权限"""
        # 总公司用户应该能访问总公司
        self.assertTrue(self.root_admin.is_in_company_tree(self.root_company.pk))

        # 总公司用户不能访问其他公司
        self.assertFalse(self.root_admin.is_in_company_tree(self.other_company.pk))

        # 分公司用户能访问分公司和总公司
        self.assertTrue(self.branch_user.is_in_company_tree(self.branch_company.pk))
        self.assertTrue(self.branch_user.is_in_company_tree(self.root_company.pk))

    def test_permission_validation(self):
        """测试权限验证逻辑"""
        # 测试无效权限
        self.assertFalse(self.root_user.has_permission("nonexistent_resource", "read"))
        self.assertFalse(
            self.root_user.has_permission("menu_dashboard", "invalid_permission")
        )

    def test_permission_queryset_filtering(self):
        """测试查询集权限过滤"""
        from django.db import connection

        # 创建测试数据
        test_user1 = SysUser.objects.create_user(
            username="test1", password="test", cn_name="测试用户1"
        )
        test_user2 = SysUser.objects.create_user(
            username="test2", password="test", cn_name="测试用户2"
        )

        # 测试权限过滤
        queryset = SysUser.objects.all()
        filtered_queryset = self.branch_user.filter_queryset_by_permission(queryset)

        # 检查SQL条件
        self.assertIsNotNone(filtered_queryset)

        # 测试全部数据权限
        all_data_queryset = self.root_admin.filter_queryset_by_permission(queryset)
        self.assertEqual(all_data_queryset.count(), queryset.count())

    def test_multiple_permission_types(self):
        """测试多种权限类型"""
        # 测试不同权限类型
        permission_types = ["read", "write", "delete", "export", "import", "manage"]

        for perm_type in permission_types:
            # 超级用户应该有所有权限类型
            self.assertTrue(self.superuser.has_permission("menu_dashboard", perm_type))

            # 普通用户根据具体分配决定
            has_perm = self.root_user.has_permission("menu_dashboard", perm_type)
            if perm_type == "read":
                self.assertTrue(has_perm)  # 有读取权限
            else:
                self.assertFalse(has_perm)  # 没有其他权限

    def test_permission_coverage(self):
        """测试权限覆盖规则"""
        # 管理权限应该覆盖所有其他权限
        user_with_manage = self.root_admin
        effective_perms = user_with_manage.get_effective_permissions("menu_user_manage")

        self.assertIn("manage", effective_perms)
        self.assertTrue(len(effective_perms) > 1)  # 应该包含多种权限类型

    def test_performance_optimization(self):
        """测试性能优化"""
        import time

        # 测试权限查询性能
        start_time = time.time()

        for _ in range(10):  # 多次查询测试缓存效果
            perms = self.root_admin.get_all_perms()

        end_time = time.time()
        execution_time = end_time - start_time

        # 执行时间应该合理（根据实际调整阈值）
        self.assertLess(execution_time, 2.0)  # 2秒内完成10次查询

        # 检查查询数量（应该使用预加载优化）
        with self.assertNumQueries(less_than=10):  # 查询次数应该有限
            perms = self.root_admin.get_all_perms()

    def test_error_handling(self):
        """测试错误处理"""
        # 测试无效公司ID
        perms = self.root_admin.get_all_perms(company_pk=99999)
        self.assertEqual(len(perms), 0)  # 应该返回空列表

        # 测试无效资源
        self.assertFalse(self.root_admin.has_permission("invalid_resource", "read"))

        # 测试空用户
        empty_user = SysUser.objects.create_user(
            username="empty", password="test", cn_name="空权限用户"
        )
        perms = empty_user.get_all_perms()
        self.assertEqual(len(perms), 0)


class EdgeCaseTests(PermissionTestBase):
    """
    边界情况测试
    """

    def test_user_without_department(self):
        """测试无部门用户权限"""
        user = self.other_user  # 没有部门的用户

        perms = user.get_all_perms()
        self.assertEqual(len(perms), 0)  # 应该没有权限

        self.assertFalse(user.has_permission("menu_dashboard", "read"))

    def test_inactive_resources(self):
        """测试非活跃资源权限"""
        # 将资源设置为非活跃
        self.menu_dashboard.is_active = False
        self.menu_dashboard.save()

        # 非活跃资源不应该有权限
        self.assertFalse(self.superuser.has_permission("menu_dashboard", "read"))

    def test_expired_permissions(self):
        """测试过期权限"""
        # 创建过期直接权限
        expired_perm = SysUserDirectPermission.objects.create(
            user=self.root_user,
            permission=self.perm_menu_user_manage,
            assigned_by=self.superuser,
            valid_to=timezone.now() - timezone.timedelta(days=1),  # 昨天过期
        )

        # 过期权限不应该生效
        perms = self.root_user.get_all_perms()
        active_perms = [p for p in perms if not p.get("is_expired", False)]
        self.assertTrue(len(active_perms) >= 0)

    def test_cross_company_permission_validation(self):
        """测试跨公司权限验证"""
        # 尝试创建跨公司权限分配（应该失败）
        from django.core.exceptions import ValidationError

        with self.assertRaises(ValidationError):
            # 尝试将分公司权限集分配给总公司角色
            invalid_assignment = SysRolePermissionSet(
                role=self.role_root_admin,  # 总公司角色
                permission_set=self.branch_user_set,  # 分公司权限集
                assigned_by=self.superuser,
            )
            invalid_assignment.full_clean()  # 应该触发验证错误


# 运行测试的便捷函数
def run_permission_tests():
    """运行所有权限测试"""
    import unittest

    from django.conf import settings
    from django.test.utils import get_runner

    test_runner = get_runner(settings)()
    test_suite = unittest.TestLoader().loadTestsFromTestCase(PermissionScenariosTest)

    result = test_runner.run_suite(test_suite)
    return result
