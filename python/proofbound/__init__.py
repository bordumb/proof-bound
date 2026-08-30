"""Small, non-authoritative helpers for Proofbound adapter processes.

The Rust CLI remains the manifest, policy, and status authority.  This package
only helps Python adapters speak the versioned canonical subprocess protocol.
"""

from .protocol import AdapterRequest, AdapterResponse, ProtocolError, canonical_json

__all__ = [
    "AdapterRequest",
    "AdapterResponse",
    "ProtocolError",
    "canonical_json",
]
