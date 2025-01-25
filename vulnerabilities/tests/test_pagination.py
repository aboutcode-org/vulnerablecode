from django.test import TestCase
from django.urls import reverse

from vulnerabilities.models import Package


class PaginationFunctionalityTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        for i in range(150):
            Package.objects.create(
                type="test",
                namespace="test",
                name=f"package{i}",
                version=str(i),
                qualifiers={},
                subpath="",
            )

    def test_default_pagination(self):
        response = self.client.get(reverse("package_search"))
        self.assertEqual(response.status_code, 200)
        page_obj = response.context["page_obj"]
        self.assertIsNotNone(page_obj)
        self.assertEqual(len(page_obj.object_list), 20)
        self.assertEqual(response.context["total_count"], 150)
        self.assertEqual(response.context["current_page_size"], 20)

    def test_page_size_variations(self):
        valid_page_sizes = [20, 50, 100]
        for size in valid_page_sizes:
            url = f"{reverse('package_search')}?page_size={size}"
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertIn(response.context["current_page_size"], [20, size])

    def test_page_navigation(self):
        response = self.client.get(reverse("package_search"))
        first_page = response.context["page_obj"]
        self.assertEqual(first_page.number, 1)
        self.assertTrue(first_page.has_next())
        self.assertFalse(first_page.has_previous())
        self.assertGreater(first_page.paginator.num_pages, 1)


class PaginationSecurityTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        for i in range(50):
            Package.objects.create(
                type="test",
                namespace="test",
                name=f"package{i}",
                version=str(i),
                qualifiers={},
                subpath="",
            )

    def test_invalid_page_size_inputs(self):
        malicious_inputs = [
            "abc",
            "-10",
            "0",
            "9999999999",
            "11",
            "<script>",
            "../../etc/passwd",
            "' OR 1=1 --",
            "",
        ]
        for input_value in malicious_inputs:
            url = f"{reverse('package_search')}?page_size={input_value}"
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.context["current_page_size"], 20)

    def test_sql_injection_prevention(self):
        sql_injection_payloads = [
            "1' OR '1'='1",
            "1; DROP TABLE packages;",
            "' UNION SELECT * FROM auth_user--",
            "1 OR 1=1",
        ]
        initial_package_count = Package.objects.count()
        for payload in sql_injection_payloads:
            urls = [
                f"{reverse('package_search')}?page={payload}",
                f"{reverse('package_search')}?page_size={payload}",
            ]
            for url in urls:
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
            self.assertEqual(Package.objects.count(), initial_package_count)


class PaginationEdgeCaseTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        for i in range(5):
            Package.objects.create(
                type="test",
                namespace="test",
                name=f"package{i}",
                version=str(i),
            )

    def test_small_dataset_pagination(self):
        response = self.client.get(reverse("package_search"))
        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(response.context["page_obj"].object_list), 20)

    def test_out_of_range_page_number(self):
        out_of_range_urls = [
            f"{reverse('package_search')}?page=9999",
            f"{reverse('package_search')}?page=-5",
            f"{reverse('package_search')}?page=abc",
        ]
        for url in out_of_range_urls:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.context["page_obj"].number, 1)
