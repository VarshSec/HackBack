"""
BOLA / IDOR Verification Engine package.
Provides modular dual-identity authentication, resource discovery,
ownership mapping, semantic differential verification, and evidence generation.
"""

from tasks.bola.auth_manager import (
    SessionIdentityManager,
    IDENTITY_PRIMARY,
    IDENTITY_SECONDARY,
    IDENTITY_ANONYMOUS,
    AuthOutcome,
    IdentityAuthState,
)

__all__ = [
    "SessionIdentityManager",
    "IDENTITY_PRIMARY",
    "IDENTITY_SECONDARY",
    "IDENTITY_ANONYMOUS",
    "AuthOutcome",
    "IdentityAuthState",
]
