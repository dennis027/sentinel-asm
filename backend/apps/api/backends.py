"""
Sign in with a username or an email address.

An email works only when exactly one active account has it: two accounts
may share an address, and guessing between them could sign someone in to
the wrong one. Every other rule (active accounts only, password check,
timing-safe failure) is Django's ModelBackend.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend


class EmailOrUsernameBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None:
            username = kwargs.get(get_user_model().USERNAME_FIELD)
        if username is None or password is None:
            return None
        User = get_user_model()
        user = User._default_manager.filter(username=username).first()
        if user is None and "@" in username:
            matches = list(User._default_manager.filter(email__iexact=username.strip(), is_active=True)[:2])
            user = matches[0] if len(matches) == 1 else None
        if user is None:
            # Same work as a real check, so a missing account can't be told
            # apart by how long the answer takes.
            User().set_password(password)
            return None
        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
