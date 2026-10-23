"""
User account management: invitations (and creating an account through
one), forgotten passwords, signing in with an email address, the
profile, changing the email address, signing out everywhere -- plus the
abuse cases each of them has to refuse.
"""

import re
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from apps.audit_logs.models import AuthEvent
from apps.organizations.models import Invitation, Membership, Organization

User = get_user_model()
PASSWORD = "Correct-horse-42!"


def link_token(message, kind):
    return re.search(rf"/{kind}/(\S+)", message.body).group(1)


class AccountFixture(TestCase):
    def setUp(self):
        cache.clear()
        self.org = Organization.objects.create(name="Acme", root_domain="acme.com")
        self.users = {}
        for role in ("owner", "admin", "analyst", "viewer"):
            user = User.objects.create_user(role, email=f"{role}@acme.com", password=PASSWORD)
            Membership.objects.create(user=user, organization=self.org, role=role)
            self.users[role] = user

    def invite(self, as_role="admin", email="new@example.com", role="analyst"):
        self.client.force_login(self.users[as_role])
        return self.client.post(f"/api/organizations/{self.org.id}/invitations/", {"email": email, "role": role},
                                content_type="application/json")

    def accept(self, token, **body):
        return self.client.post(f"/api/invitations/{token}/accept/", body, content_type="application/json")

    def login(self, username, password=PASSWORD):
        return self.client.post("/api/auth/login/", {"username": username, "password": password},
                                content_type="application/json")


class InvitationTests(AccountFixture):
    def test_invite_sends_a_link_and_a_new_person_creates_their_account_with_it(self):
        response = self.invite(email="New@Example.com")
        self.assertEqual(response.status_code, 201, response.content)
        body = response.json()
        self.assertEqual((body["email"], body["role"], body["status"], body["email_sent"]),
                         ("new@example.com", "analyst", "pending", True))
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["new@example.com"])
        token = link_token(mail.outbox[0], "invite")
        self.assertTrue(body["invite_link"].endswith(token))
        # Only a hash is kept.
        self.assertNotIn(token, Invitation.objects.get().token_hash)

        self.client.logout()
        detail = self.client.get(f"/api/invitations/{token}/").json()
        self.assertEqual((detail["organization"], detail["role_label"], detail["status"], detail["account_exists"]),
                         ("Acme", "Security Analyst", "pending", False))

        self.assertEqual(self.accept(token, password="short").status_code, 400)
        joined = self.accept(token, password=PASSWORD, first_name="Nia", last_name="Wanjiku")
        self.assertEqual(joined.status_code, 200, joined.content)
        self.assertTrue(joined.json()["created_account"])
        self.assertIn("access", joined.json())
        user = User.objects.get(email="new@example.com")
        self.assertEqual((user.username, user.get_full_name()), ("new@example.com", "Nia Wanjiku"))
        self.assertEqual(Membership.objects.get(user=user, organization=self.org).role, "analyst")
        self.assertTrue(AuthEvent.objects.filter(user=user, event_type="account_created").exists())

        # The link works once.
        again = self.accept(token, password=PASSWORD)
        self.assertEqual(again.status_code, 410)
        self.assertEqual(self.login("new@example.com").status_code, 200)

    def test_only_admins_invite_and_only_owners_invite_owners(self):
        self.assertEqual(self.invite(as_role="analyst").status_code, 403)
        self.assertEqual(self.invite(as_role="admin", role="owner").status_code, 403)
        self.assertEqual(self.invite(as_role="owner", role="owner").status_code, 201)

    def test_members_and_waiting_invitations_cannot_be_invited_twice(self):
        self.assertIn("already a member", self.invite(email="VIEWER@acme.com").json()["email"][0])
        self.invite(email="new@example.com")
        self.assertIn("Resend", self.invite(email="new@example.com").json()["email"][0])

    def test_an_existing_account_must_sign_in_as_the_invited_address(self):
        outsider = User.objects.create_user("sam", email="sam@example.com", password=PASSWORD)
        self.invite(email="sam@example.com")
        token = link_token(mail.outbox[-1], "invite")
        self.client.logout()
        self.assertTrue(self.client.get(f"/api/invitations/{token}/").json()["account_exists"])
        self.assertEqual(self.accept(token, password=PASSWORD).json()["code"], "sign_in_required")

        self.client.force_login(self.users["viewer"])
        self.assertEqual(self.accept(token).json()["code"], "wrong_account")

        self.client.force_login(outsider)
        joined = self.accept(token)
        self.assertEqual(joined.status_code, 200)
        self.assertFalse(joined.json()["created_account"])
        self.assertTrue(Membership.objects.filter(user=outsider, organization=self.org, role="analyst").exists())

    def test_resend_replaces_the_link_and_cancel_kills_it(self):
        invitation_id = self.invite().json()["id"]
        first = link_token(mail.outbox[-1], "invite")
        resent = self.client.post(f"/api/organizations/{self.org.id}/invitations/{invitation_id}/resend/")
        self.assertEqual(resent.status_code, 200)
        second = link_token(mail.outbox[-1], "invite")
        self.assertNotEqual(first, second)
        self.assertEqual(self.client.get(f"/api/invitations/{first}/").status_code, 404)

        listed = self.client.get(f"/api/organizations/{self.org.id}/invitations/").json()
        self.assertEqual([i["email"] for i in listed], ["new@example.com"])
        self.assertEqual(self.client.delete(f"/api/organizations/{self.org.id}/invitations/{invitation_id}/").status_code,
                         204)
        self.assertEqual(self.client.get(f"/api/organizations/{self.org.id}/invitations/").json(), [])
        self.client.logout()
        self.assertEqual(self.accept(second, password=PASSWORD).json()["status"], "revoked")

    def test_expired_links_are_refused(self):
        self.invite()
        token = link_token(mail.outbox[-1], "invite")
        Invitation.objects.update(expires_at=timezone.now() - timedelta(minutes=1))
        self.client.logout()
        self.assertEqual(self.accept(token, password=PASSWORD).status_code, 410)
        self.assertFalse(User.objects.filter(email="new@example.com").exists())

    def test_viewers_cannot_see_invitations(self):
        self.client.force_login(self.users["viewer"])
        self.assertEqual(self.client.get(f"/api/organizations/{self.org.id}/invitations/").status_code, 403)


class PasswordResetTests(AccountFixture):
    def request_reset(self, email):
        return self.client.post("/api/auth/password-reset/", {"email": email}, content_type="application/json")

    def confirm(self, uid, token, password):
        return self.client.post("/api/auth/password-reset/confirm/",
                                {"uid": uid, "token": token, "new_password": password}, content_type="application/json")

    def test_the_answer_never_reveals_whether_an_account_exists(self):
        unknown = self.request_reset("nobody@example.com")
        known = self.request_reset("viewer@acme.com")
        self.assertEqual((unknown.status_code, unknown.json()), (known.status_code, known.json()))
        self.assertEqual([m.to for m in mail.outbox], [["viewer@acme.com"]])

    def test_reset_changes_the_password_signs_out_everywhere_and_works_once(self):
        session = self.login("viewer").json()
        self.request_reset("viewer@acme.com")
        uid, token = link_token(mail.outbox[-1], "reset-password").split("/")

        self.assertEqual(self.confirm(uid, token, "password").status_code, 400)  # too common
        done = self.confirm(uid, token, "A-brand-new-secret-9")
        self.assertEqual(done.status_code, 200, done.content)
        self.assertEqual(self.login("viewer", "A-brand-new-secret-9").status_code, 200)
        self.assertEqual(self.login("viewer").status_code, 401)
        # Every device signed out: the old refresh token is dead.
        refreshed = self.client.post("/api/token/refresh/", {"refresh": session["refresh"]},
                                     content_type="application/json")
        self.assertEqual(refreshed.status_code, 401)
        self.assertIn("password was changed", mail.outbox[-1].subject)
        # The link was spent.
        self.assertEqual(self.confirm(uid, token, "Another-new-secret-7").json()["token"][0][:12], "This link is")
        self.assertTrue(AuthEvent.objects.filter(user=self.users["viewer"], event_type="password_reset").exists())

    def test_bad_links_and_inactive_accounts(self):
        self.assertEqual(self.confirm("bm90LWEtdWlk", "nope", "A-brand-new-secret-9").status_code, 400)
        self.users["viewer"].is_active = False
        self.users["viewer"].save()
        self.request_reset("viewer@acme.com")
        self.assertEqual(mail.outbox, [])

    def test_requests_are_rate_limited(self):
        with patch("rest_framework.throttling.ScopedRateThrottle.THROTTLE_RATES", {"password_reset": "2/hour"}):
            codes = [self.request_reset("viewer@acme.com").status_code for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])


class SignInAndProfileTests(AccountFixture):
    def test_sign_in_with_an_email_unless_two_accounts_share_it(self):
        self.assertEqual(self.login("Analyst@ACME.com").status_code, 200)
        User.objects.create_user("analyst2", email="analyst@acme.com", password=PASSWORD)
        self.assertEqual(self.login("analyst@acme.com").status_code, 401)
        self.assertEqual(self.login("analyst").status_code, 200)

    def test_profile_and_changing_the_email_address(self):
        self.client.force_login(self.users["viewer"])
        me = self.client.get("/api/auth/me/").json()
        self.assertEqual((me["username"], me["email"], me["two_factor_enabled"]), ("viewer", "viewer@acme.com", False))
        updated = self.client.patch("/api/auth/me/", {"first_name": " Chloe ", "username": "hacked"},
                                    content_type="application/json").json()
        self.assertEqual((updated["first_name"], updated["username"]), ("Chloe", "viewer"))

        change = "/api/auth/me/email/"
        self.assertEqual(self.client.post(change, {"email": "c@new.com", "current_password": "wrong"},
                                          content_type="application/json").status_code, 400)
        self.assertIn("Another account", self.client.post(
            change, {"email": "ADMIN@acme.com", "current_password": PASSWORD}, content_type="application/json"
        ).json()["email"][0])
        ok = self.client.post(change, {"email": "c@new.com", "current_password": PASSWORD},
                              content_type="application/json")
        self.assertEqual(ok.json()["email"], "c@new.com")
        self.assertEqual(mail.outbox[-1].to, ["viewer@acme.com"])  # the old address is told

    def test_sign_out_everywhere(self):
        first = self.login("viewer").json()
        second = self.login("viewer").json()
        self.client.force_login(self.users["viewer"])
        self.assertEqual(self.client.post("/api/auth/sessions/revoke/").json()["signed_out"], 2)
        for session in (first, second):
            self.assertEqual(self.client.post("/api/token/refresh/", {"refresh": session["refresh"]},
                                              content_type="application/json").status_code, 401)


class ClientErrorTests(TestCase):
    def test_browser_errors_are_logged_like_backend_errors(self):
        with self.assertLogs("apps.client", level="ERROR") as logs:
            response = self.client.post("/api/client-errors/", {
                "message": "Cannot read properties of undefined (reading 'id')", "type": "TypeError",
                "stack": "TypeError: x\n    at Findings.load (main.js:1:200)", "url": "https://app/findings",
            }, content_type="application/json")
        self.assertEqual(response.status_code, 204)
        record = logs.records[0]
        self.assertEqual((record.error["type"], record.page_url, record.service), ("TypeError", "https://app/findings",
                                                                                  "densight-web"))


class ApiRateLimitTests(AccountFixture):
    def test_every_endpoint_has_a_per_user_ceiling(self):
        self.client.force_login(self.users["viewer"])
        with patch("rest_framework.throttling.UserRateThrottle.THROTTLE_RATES", {"user": "3/min", "anon": "3/min"}):
            codes = [self.client.get("/api/organizations/").status_code for _ in range(4)]
        self.assertEqual(codes, [200, 200, 200, 429])
