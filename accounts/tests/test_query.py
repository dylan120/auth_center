from django.test import TestCase

from accounts.models.user import SysCompany, SysDepartment


class SysDepartmentTest(TestCase):
    """测试 SysDepartment 模型的查询功能"""

    def setUp(self):
        """测试前准备：创建测试数据"""
        company = SysCompany.objects.create(company_name="公司A")
        SysDepartment.objects.create(
            dept_name="运维",
            dept_code="yunwei",
            company=company,
        )
        SysDepartment.objects.create(
            dept_name="后台",
            dept_code="houtai",
            company=company,
        )

    def test_creation(self):
        """测试模型能否正确创建"""
        dept = SysDepartment.objects.get(dept_name="运维")
        self.assertEqual(dept.dept_name, "运维")
        self.assertEqual(dept.dept_code, "yunwei")

    def test_query_all(self):
        """测试查询所有"""
        companies = SysDepartment.objects.all()
        self.assertEqual(companies.count(), 2)

    def test_filter_by_name(self):
        """测试过滤"""
        dept = SysDepartment.objects.filter(dept_name__icontains="运")
        self.assertEqual(dept.count(), 1)
        self.assertEqual(dept[0].dept_name, "运维")

    def test_ordering(self):
        """测试排序"""
        dept = SysDepartment.objects.order_by("created_time")
        self.assertEqual(dept[0].dept_name, "运维")

    def test_get_available_roles(self):
        dept = SysDepartment.objects.get(dept_name="运维")
        print(dept.get_available_roles())
