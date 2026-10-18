import os
from unittest.mock import patch

from django.test import TestCase


class HealthTests(TestCase):
    def test_reports_the_running_commit(self):
        with patch.dict(os.environ, {"RENDER_GIT_COMMIT": "abc123"}):
            body = self.client.get("/health/").json()
        self.assertEqual((body["status"], body["version"]), ("ok", "abc123"))
