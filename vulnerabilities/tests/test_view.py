from django.test import Client
from django.test import TestCase


class PackageSearchTestCase(TestCase):
    def setUp(self):
        self.client = Client()

    def test_paginator(self):
        """
        Test PackageSearch paginator
        """
        response = self.client.get("/packages/search?type=deb&name=&page=1")
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/packages/search?type=deb&name=&page=*")
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/packages/search?type=deb&name=&page=")
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/packages/search?type=&name=&page=")
        self.assertEqual(response.status_code, 200)
