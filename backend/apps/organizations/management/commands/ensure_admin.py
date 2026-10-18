"""
Makes sure the admin user from DJANGO_SUPERUSER_USERNAME / _EMAIL /
_PASSWORD exists with that email and password -- for hosts without a
shell (Render's free plan), where createsuperuser can't be run by hand.
Run on every start, so changing the password setting takes effect on the
next restart.
"""

import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Create or update the admin user from DJANGO_SUPERUSER_USERNAME, _EMAIL and _PASSWORD."

    def handle(self, *args, **options):
        username = os.environ.get("DJANGO_SUPERUSER_USERNAME", "").strip()
        password = os.environ.get("DJANGO_SUPERUSER_PASSWORD", "")
        email = os.environ.get("DJANGO_SUPERUSER_EMAIL", "").strip()
        if not username or not password:
            raise CommandError("Set DJANGO_SUPERUSER_USERNAME and DJANGO_SUPERUSER_PASSWORD.")
        User = get_user_model()
        user, created = User.objects.get_or_create(username=username, defaults={"email": email})
        user.email = email or user.email
        user.is_staff = user.is_superuser = user.is_active = True
        user.set_password(password)
        user.save()
        self.stdout.write(f"Admin user {username} {'created' if created else 'updated'}.")
