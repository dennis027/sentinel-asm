import os
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.test import TestCase

ENV = {"DJANGO_SUPERUSER_USERNAME": "admin@acme.com", "DJANGO_SUPERUSER_EMAIL": "admin@acme.com",
       "DJANGO_SUPERUSER_PASSWORD": "First-pass-123!"}


class EnsureAdminTests(TestCase):
    def test_creates_then_updates_the_admin_and_can_sign_in_with_an_email_username(self):
        with patch.dict(os.environ, ENV):
            call_command("ensure_admin", stdout=StringIO())
        user = get_user_model().objects.get(username="admin@acme.com")
        self.assertTrue(user.is_superuser and user.is_staff)
        self.assertTrue(user.check_password("First-pass-123!"))

        with patch.dict(os.environ, {**ENV, "DJANGO_SUPERUSER_PASSWORD": "Second-pass-456!"}):
            call_command("ensure_admin", stdout=StringIO())
        user.refresh_from_db()
        self.assertTrue(user.check_password("Second-pass-456!"))
        self.assertEqual(get_user_model().objects.count(), 1)

        response = self.client.post("/api/token/", {"username": "admin@acme.com", "password": "Second-pass-456!"},
                                    content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.json())

    def test_missing_settings_are_a_clear_error(self):
        with patch.dict(os.environ, {"DJANGO_SUPERUSER_USERNAME": "", "DJANGO_SUPERUSER_PASSWORD": ""}):
            with self.assertRaises(CommandError):
                call_command("ensure_admin", stdout=StringIO())
