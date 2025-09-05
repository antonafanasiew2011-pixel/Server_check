from typing import Optional
from ldap3 import Server, Connection, ALL, Tls
from app.config import settings


def ldap_authenticate(username: str, password: str) -> Optional[dict]:
    if not settings.ldap_enabled:
        return None

    if not (settings.ldap_server and settings.ldap_user_base_dn):
        return None

    server = Server(settings.ldap_server, port=settings.ldap_port, use_ssl=settings.ldap_use_ssl, get_info=ALL)

    user_filter = settings.ldap_user_filter.format(username=username)
    bind_dn = settings.ldap_bind_dn
    bind_password = settings.ldap_bind_password

    try:
        if bind_dn and bind_password:
            with Connection(server, user=bind_dn, password=bind_password, auto_bind=True) as conn:
                search_base = settings.ldap_user_base_dn
                conn.search(search_base=search_base, search_filter=user_filter, attributes=["distinguishedName", "cn", "memberOf"])
                if not conn.entries:
                    return None
                user_dn = conn.entries[0].entry_dn
                groups = [str(g) for g in getattr(conn.entries[0], 'memberOf', [])]
        else:
            # If no bind credentials provided, try user bind directly
            user_dn = None
            groups = []

        if user_dn:
            with Connection(server, user=user_dn, password=password, auto_bind=True) as _:
                return {"dn": user_dn, "groups": groups}
        else:
            # Attempt simple bind as username in base dn
            tentative_dn = f"cn={username},{settings.ldap_user_base_dn}"
            with Connection(server, user=tentative_dn, password=password, auto_bind=True) as _:
                return {"dn": tentative_dn, "groups": groups}
    except Exception:
        return None


