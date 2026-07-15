"""Cantica Secure — shimmable authentication/authorization core.

Public surface: SecurityShim, SecureConfig, CurrentUser, require_permission,
SmtpMailTransport. Everything else is implementation detail.
"""

from cantica_secure.api.deps import CurrentUser, CurrentUserDep, get_current_user, require_permission
from cantica_secure.config import SecureConfig
from cantica_secure.mail import MailTransport, SmtpMailTransport
from cantica_secure.shim import SecurityShim

__all__ = [
    "CurrentUser",
    "CurrentUserDep",
    "MailTransport",
    "SecureConfig",
    "SecurityShim",
    "SmtpMailTransport",
    "get_current_user",
    "require_permission",
]
