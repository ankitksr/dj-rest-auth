import uuid

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.utils import timezone
from rest_framework.authtoken.models import Token as DefaultTokenModel

from .app_settings import api_settings


def get_token_model():
    token_model = api_settings.TOKEN_MODEL
    session_login = api_settings.SESSION_LOGIN
    use_jwt = api_settings.USE_JWT

    if not any((session_login, token_model, use_jwt)):
        raise ImproperlyConfigured(
            'No authentication is configured for rest auth. You must enable one or '
            'more of `TOKEN_MODEL`, `USE_JWT` or `SESSION_LOGIN`'
        )
    if (
        token_model == DefaultTokenModel and 'rest_framework.authtoken' not in settings.INSTALLED_APPS
    ):
        raise ImproperlyConfigured(
            'You must include `rest_framework.authtoken` in INSTALLED_APPS '
            'or set TOKEN_MODEL to None'
        )
    return token_model


TokenModel = get_token_model()


class LoginVerificationCode(models.Model):
    """
    Stores and manages email-based login verification codes.
    Used as part of the two-factor authentication process during login.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    last_verified_at = models.DateTimeField(null=True)

    def __str__(self):
        return f"Login verification code for {self.user.email}"

    def save(self, *args, **kwargs):
        if not self.code:
            from allauth.account.adapter import get_adapter

            self.code = get_adapter().generate_login_code()

        if not self.expires_at:
            from allauth.account import app_settings as allauth_account_settings

            self.expires_at = timezone.now() + timezone.timedelta(seconds=allauth_account_settings.LOGIN_BY_CODE_TIMEOUT)

        super().save(*args, **kwargs)

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @property
    def needs_new_verification(self):
        if not self.last_verified_at:
            return True

        cutoff_time = timezone.now()
        if grace_period := api_settings.LOGIN_BY_CODE_GRACE_PERIOD:
            cutoff_time = timezone.now() - grace_period

        return self.last_verified_at < cutoff_time

    class Meta:
        verbose_name = 'Login Verification Code'
        verbose_name_plural = 'Login Verification Codes'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['last_verified_at']),
            models.Index(fields=['user', 'is_verified']),
        ]
