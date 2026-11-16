"""Global network/origin policy and session-bound CSRF validation."""
import ipaddress
import secrets
from urllib.parse import urlsplit

from fastapi import HTTPException

CSRF_COOKIE = 'ptm_csrf'


# Explicit ranges: ipaddress.is_private also includes documentation/reserved networks.
from .config import PRIVATE_NETWORKS
LAN_NETWORKS=tuple(ipaddress.ip_network(value) for value in PRIVATE_NETWORKS)
PROXY_HEADERS={'forwarded','x-forwarded-for','x-forwarded-host','x-forwarded-proto','x-real-ip'}


def lan_address(value):
    try:
        address=ipaddress.ip_address(value)
        if getattr(address,'ipv4_mapped',None):address=address.ipv4_mapped
        return any(address in network for network in LAN_NETWORKS)
    except ValueError:return False


def interface_mode():
    from . import projects
    cfg=projects.base_settings
    return cfg.lan_access and any(ipaddress.ip_network(network).prefixlen==0 for network in cfg.management_networks)


def direct_lan_http_allowed(request):
    from . import projects
    return (projects.base_settings.lan_access and request.client is not None
            and (interface_mode() or lan_address(request.client.host))
            and not any(name in request.headers for name in PROXY_HEADERS))


def remote_setup_allowed(request):
    from . import projects
    return projects.base_settings.remote_setup and direct_lan_http_allowed(request)


def management_client_allowed(request):
    if request.client is None:
        return False
    try:
        address = ipaddress.ip_address(request.client.host)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        from . import projects
        return any(address in ipaddress.ip_network(network) for network in projects.base_settings.management_networks)
    except ValueError:
        return False


def management_host_allowed(request):
    host = request.url.hostname
    from . import projects
    if host in projects.base_settings.trusted_hosts:
        return True
    if interface_mode():
        from .interfaces import local_host
        return local_host(host)
    try:
        address = ipaddress.ip_address(host or '')
        if getattr(address,'ipv4_mapped',None):address=address.ipv4_mapped
        from . import projects
        return any(address in ipaddress.ip_network(network) for network in projects.base_settings.management_networks)
    except ValueError:
        return False


def same_origin(request):
    origin = request.headers.get('origin')
    if request.headers.get('sec-fetch-site') == 'cross-site':
        return False
    if not origin:
        return True  # Non-browser clients must still provide the CSRF token.
    try:
        parsed = urlsplit(origin)
        expected = request.url
        return (parsed.scheme in ('http', 'https') and not parsed.username and not parsed.password
                and parsed.path in ('', '/') and not parsed.query and not parsed.fragment
                and parsed.scheme == expected.scheme and parsed.hostname == expected.hostname
                and (parsed.port or (443 if parsed.scheme == 'https' else 80))
                == (expected.port or (443 if expected.scheme == 'https' else 80)))
    except ValueError:
        return False


def valid_csrf(expected,submitted):
    return (isinstance(submitted,str) and len(submitted)==64 and
            all(c in '0123456789abcdef' for c in submitted) and
            secrets.compare_digest(expected,submitted))


def require_management(request,submitted_token):
    user=getattr(request.state,'user',None)
    if not user or user['role']!='administrator':raise HTTPException(403,'Требуется Administrator')
    if not valid_csrf(request.state.csrf_token,submitted_token):raise HTTPException(403,'Неверный защитный токен')
