"""Cantica Secure — shimmable authentication/authorization core.

Public surface: SecurityShim, SecureConfig, CurrentUser, require_permission,
SmtpMailTransport. Everything else is implementation detail.
"""

from cantica_secure.api.deps import CurrentUser, CurrentUserDep, get_current_user, require_permission
from cantica_secure.config import SecureConfig
from cantica_secure.mail import MailTransport, SmtpMailTransport
from cantica_secure.presets import (
    CANTICA_PERMISSIONS,
    CANTICA_ROLES,
    STUDIO_PERMISSIONS,
    STUDIO_ROLES,
)
from cantica_secure.shim import PrincipalAdapter, SecurityShim, UserEventCallback

__all__ = [
    "CANTICA_PERMISSIONS",
    "CANTICA_ROLES",
    "STUDIO_PERMISSIONS",
    "STUDIO_ROLES",
    "PrincipalAdapter",
    "UserEventCallback",
    "CurrentUser",
    "CurrentUserDep",
    "MailTransport",
    "SecureConfig",
    "SecurityShim",
    "SmtpMailTransport",
    "get_current_user",
    "require_permission",
]
