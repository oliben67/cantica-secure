"""LdapBackend — bind user against LDAP/AD, resolve group membership.

Flow: bind with the (optional) service account, search the user entry by
email under base_dn, then re-bind with the found DN and the supplied password.
Identity attributes (givenName, sn, mail, memberOf) feed directory
provisioning; memberOf values are mapped to roles via directory_group_roles.

`ldap3` is imported lazily — install the "ldap" extra to use this backend.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from cantica_secure.backends.base import AuthResult
from cantica_secure.backends.provision import provision_directory_user

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from cantica_secure.orm.models import User

log = logging.getLogger(__name__)


def _first(value: object) -> str:
    """LDAP attributes arrive as lists; return the first value as a string."""
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else ""
    return str(value) if value else ""


class LdapBackend:
    """
    Bind user against LDAP, resolve group membership from a configured attribute.
    credential = email, secret = password.
    """

    def __init__(
        self,
        host: str,
        port: int,
        base_dn: str,
        group_attr: str,
        default_roles: list[str],
        bind_dn: str = "",
        bind_password: str = "",
        user_filter: str = "(mail={email})",
    ) -> None:
        self._host = host
        self._port = port
        self._base_dn = base_dn
        self._group_attr = group_attr
        self._default_roles = default_roles
        self._bind_dn = bind_dn
        self._bind_password = bind_password
        self._user_filter = user_filter

    @classmethod
    def from_config(cls, config) -> "LdapBackend":
        return cls(
            host=config.ldap_host,
            port=config.ldap_port,
            base_dn=config.ldap_base_dn,
            group_attr=config.ldap_group_attr,
            default_roles=config.default_roles,
            bind_dn=config.ldap_bind_dn,
            bind_password=config.ldap_bind_password,
            user_filter=config.ldap_user_filter,
        )

    def _ldap3(self):  # noqa: ANN202 — module type
        try:
            import ldap3  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError(
                "LDAP backend requires the 'ldap3' package — install cantica-secure with the [ldap] extra"
            ) from exc
        return ldap3

    def authenticate(self, credential: str, secret: str) -> AuthResult | None:
        if not secret:
            return None  # empty password would be an anonymous bind — always reject
        ldap3 = self._ldap3()
        server = ldap3.Server(self._host, port=self._port, get_info=None)

        # 1. Search for the user entry (service account or anonymous bind).
        try:
            search_conn = ldap3.Connection(
                server,
                user=self._bind_dn or None,
                password=self._bind_password or None,
                auto_bind=True,
            )
            search_conn.search(
                self._base_dn,
                self._user_filter.format(email=credential),
                attributes=["givenName", "sn", "mail", "objectGUID", self._group_attr],
            )
            entries = list(search_conn.entries)
            search_conn.unbind()
        except Exception as exc:
            log.warning("LDAP search failed: %s", exc)
            return None
        if not entries:
            return None
        entry = entries[0]
        user_dn = entry.entry_dn
        attrs = entry.entry_attributes_as_dict

        # 2. Verify the password by binding as the user.
        try:
            user_conn = ldap3.Connection(server, user=user_dn, password=secret, auto_bind=True)
            user_conn.unbind()
        except Exception:
            return None

        raw_groups = attrs.get(self._group_attr) or []
        groups = [str(g) for g in raw_groups]

        return AuthResult(
            user_id="",  # resolved / created by sync_user
            email=_first(attrs.get("mail")) or credential,
            e_user_id=_first(attrs.get("objectGUID")) or user_dn,
            first_name=_first(attrs.get("givenName")),
            last_name=_first(attrs.get("sn")),
            directory_groups=groups,
        )

    def sync_user(self, session: "Session", result: AuthResult) -> "User":
        return provision_directory_user(session, result, default_roles=self._default_roles)
