"""
Screenshots in object storage (R2/S3) or on disk: the scanner, the API
that streams them and organization deletion must work with any storage,
not just files on the local disk. Checked against Django's in-memory
storage, which has no files at all.
"""

from django.contrib.auth.models import User
from django.core.files.storage import default_storage
from django.test import SimpleTestCase, TestCase, override_settings

from apps.assets.models import Asset
from apps.findings.models import Finding
from apps.organizations.deletion import delete_organization
from apps.organizations.models import Membership, Organization
from apps.scanning import screenshot_store

IN_MEMORY = {
    "default": {"BACKEND": "django.core.files.storage.InMemoryStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}
PNG = b"\x89PNG\r\n\x1a\nfake"


class PathSafetyTests(SimpleTestCase):
    def test_only_paths_inside_screenshots_are_accepted(self):
        self.assertEqual(screenshot_store.safe("screenshots/1/a.png"), "screenshots/1/a.png")
        for bad in ("../settings.py", "screenshots/../../etc/passwd", "/etc/passwd", "media/x.png", "", None, 3):
            self.assertIsNone(screenshot_store.safe(bad), bad)


@override_settings(STORAGES=IN_MEMORY)
class ObjectStorageTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", root_domain="acme.com")
        self.asset = Asset.objects.create(organization=self.org, value="shop.acme.com", asset_type=Asset.AssetType.SUBDOMAIN)
        self.user = User.objects.create_user("viewer", password="pass12345!")
        Membership.objects.create(user=self.user, organization=self.org, role="viewer")

    def screenshot(self, path):
        return Finding.objects.create(asset=self.asset, finding_type=Finding.FindingType.SCREENSHOT, severity="info",
                                      title="Screenshot", raw_data={"screenshot_path": path},
                                      dedupe_key=Finding.build_dedupe_key("screenshot", path))

    def test_saved_screenshots_are_streamed_to_signed_in_members(self):
        path = screenshot_store.save(screenshot_store.path_for(self.asset.id, "20261019T000000Z-00.png"), PNG)
        self.assertEqual(path, f"screenshots/{self.asset.id}/20261019T000000Z-00.png")
        finding = self.screenshot(path)

        self.client.force_login(self.user)
        response = self.client.get(f"/api/findings/{finding.id}/screenshot/")
        self.assertEqual((response.status_code, response["Content-Type"]), (200, "image/png"))
        self.assertEqual(b"".join(response.streaming_content), PNG)
        self.assertEqual(self.client.get(f"/api/findings/{self.screenshot('../../secret').id}/screenshot/").status_code, 404)
        self.assertEqual(self.client.get(f"/api/findings/{self.screenshot('screenshots/x/gone.png').id}/screenshot/").status_code, 404)

    def test_deleting_an_organization_deletes_its_screenshots_only(self):
        other_org = Organization.objects.create(name="Other", root_domain="other.com")
        other = Asset.objects.create(organization=other_org, value="other.com", asset_type=Asset.AssetType.DOMAIN)
        mine = [screenshot_store.save(screenshot_store.path_for(self.asset.id, f"{n}.png"), PNG) for n in range(3)]
        theirs = screenshot_store.save(screenshot_store.path_for(other.id, "0.png"), PNG)
        delete_organization(self.org)
        self.assertFalse(any(default_storage.exists(p) for p in mine))
        self.assertTrue(default_storage.exists(theirs))


class R2ConfigurationTests(SimpleTestCase):
    def test_r2_settings_give_private_keys_under_the_prefix(self):
        from storages.backends.s3 import S3Storage

        storage = S3Storage(bucket_name="densight", endpoint_url="https://abc123.r2.cloudflarestorage.com",
                            access_key="key", secret_key="secret", region_name="auto", location="media",
                            default_acl=None, querystring_auth=True, file_overwrite=False, signature_version="s3v4")
        self.assertEqual(storage._normalize_name("screenshots/1/a.png"), "media/screenshots/1/a.png")
        self.assertIsNone(storage.default_acl)
