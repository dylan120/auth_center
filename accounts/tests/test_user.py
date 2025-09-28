# tests/test_user.py
import pytest
from django.contrib.auth import get_user_model
from django.test import TestCase

from accounts.models import (
    SysCompany,
    SysDepartment,
    SysDepartmentRole,
    SysRole,
    SysUser,
    SysUserDepartment,
    SysUserRole,
)


class SysUserModelTest(TestCase):
    """SysUser 模型测试类"""

    def setUp(self):
        """测试数据准备"""
        # 创建公司
        self.company = SysCompany.objects.create(
            company_name="测试公司", status=SysCompany.COMPANY_STATUS_ACTIVE
        )

        # 创建部门
        self.department = SysDepartment.objects.create(
            dept_name="测试部门", dept_code="test_dept", company=self.company
        )

        # 创建角色
        self.role = SysRole.objects.create(
            role_name="测试角色", role_code="test_role", company=self.company
        )

        # 创建用户
        self.user_data = {
            "username": "testuser",
            "password": "testpass123",
            "cn_name": "测试用户",
            "email": "test@example.com",
        }

    def test_create_user(self):
        """测试创建用户"""
        user = SysUser.objects.create_user(**self.user_data)

        self.assertEqual(user.username, "testuser")
        self.assertEqual(user.cn_name, "测试用户")
        self.assertTrue(user.check_password("testpass123"))
        self.assertFalse(user.is_superuser)
        self.assertTrue(user.is_active)

    def test_create_superuser(self):
        """测试创建超级用户"""
        superuser = SysUser.objects.create_superuser(
            username="admin", password="admin123", cn_name="管理员"
        )

        self.assertEqual(superuser.username, "admin")
        self.assertTrue(superuser.is_superuser)
        self.assertTrue(superuser.is_staff)

    def test_user_company_relationship(self):
        """测试用户与公司关系"""
        user = SysUser.objects.create_user(**self.user_data)

        # 关联用户到部门
        SysUserDepartment.objects.create(department=self.department, user=user)

        company = user.get_company()
        self.assertEqual(company, self.company)

    def test_user_roles(self):
        """测试用户角色分配"""
        user = SysUser.objects.create_user(**self.user_data)

        # 分配角色给用户
        SysUserRole.objects.create(user=user, role=self.role)

        roles = user.get_personal_roles()
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0], self.role)

    def test_user_permissions(self):
        """测试用户权限检查"""
        user = SysUser.objects.create_user(**self.user_data)

        # 超级用户有所有权限
        superuser = SysUser.objects.create_superuser(
            username="superadmin", password="super123", cn_name="超级管理员"
        )

        self.assertTrue(superuser.has_permission("any_resource", "read"))
        self.assertFalse(user.has_permission("any_resource", "read"))

    def test_password_hashing(self):
        """测试密码加密"""
        user = SysUser.objects.create_user(**self.user_data)

        # 检查密码是否正确加密
        self.assertTrue(user.check_password("testpass123"))
        self.assertFalse(user.check_password("wrongpassword"))

        # 测试修改密码
        user.set_password("newpassword123")
        self.assertTrue(user.check_password("newpassword123"))

    def test_user_string_representation(self):
        """测试用户字符串表示"""
        user = SysUser.objects.create_user(**self.user_data)
        self.assertEqual(str(user), "测试用户")

        # 测试没有cn_name的情况
        user2 = SysUser.objects.create_user(username="user2", password="pass123")
        self.assertEqual(str(user2), "user2")

    def test_user_department_roles(self):
        """测试用户通过部门获取角色"""
        user = SysUser.objects.create_user(**self.user_data)

        # 关联用户到部门
        SysUserDepartment.objects.create(department=self.department, user=user)

        # 分配角色到部门
        SysDepartmentRole.objects.create(department=self.department, role=self.role)

        dept_roles = user.get_department_roles()
        self.assertEqual(len(dept_roles), 1)
        self.assertEqual(dept_roles[0], self.role)

    def test_user_all_roles(self):
        """测试获取用户所有角色"""
        user = SysUser.objects.create_user(**self.user_data)

        # 个人角色
        SysUserRole.objects.create(user=user, role=self.role)

        # 部门角色
        SysUserDepartment.objects.create(department=self.department, user=user)
        dept_role = SysRole.objects.create(
            role_name="部门角色", role_code="dept_role", company=self.company
        )
        SysDepartmentRole.objects.create(department=self.department, role=dept_role)

        all_roles = user.get_all_roles()
        self.assertEqual(len(all_roles), 2)

    def test_user_company_filter(self):
        """测试按公司过滤用户角色"""
        user = SysUser.objects.create_user(**self.user_data)

        # 创建另一个公司
        other_company = SysCompany.objects.create(
            company_name="其他公司", status=SysCompany.COMPANY_STATUS_ACTIVE
        )
        other_role = SysRole.objects.create(
            role_name="其他公司角色", role_code="other_role", company=other_company
        )

        # 分配两个公司的角色
        SysUserRole.objects.create(user=user, role=self.role)  # 当前公司
        SysUserRole.objects.create(user=user, role=other_role)  # 其他公司

        # 按公司过滤
        company_roles = user.get_company_roles(self.company.pk)
        self.assertEqual(len(company_roles), 1)
        self.assertEqual(company_roles[0], self.role)

    @pytest.mark.django_db
    def test_user_authentication(self):
        """测试用户认证"""
        user = SysUser.objects.create_user(**self.user_data)

        # 使用Django认证系统
        from django.contrib.auth import authenticate

        authenticated_user = authenticate(username="testuser", password="testpass123")

        self.assertEqual(authenticated_user, user)
