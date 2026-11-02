from .base import RemoteApp as BaseRemoteApp
from .oidc import OIDCRemoteApp

__all__ = [
    "BaseRemoteApp",
    "OIDCRemoteApp",
]
