from django.test import TestCase, Client


class PackageSearchTestCase(TestCase):
    def setUp(self):
        self.client = Client()

    def test_paginator(self):
        response = self.client.get('/packages/search?type=deb&name=&page=1')
        self.assertEqual(response.status_code, 200)

        response = self.client.get('/packages/search?type=deb&name=&page=*')
        self.assertEqual(response.status_code, 200)

        response = self.client.get('/packages/search?type=deb&name=&page=')
        self.assertEqual(response.status_code, 200)

        response = self.client.get('/packages/search?type=&name=&page=')
        self.assertEqual(response.status_code, 200)
