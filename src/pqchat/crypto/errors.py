"""Single opaque error type for every cryptographic failure.

Messages are deliberately generic: they never contain key material and do not reveal
*which* internal check failed beyond what the caller already knows.
"""


class CryptoError(Exception):
    """A cryptographic operation or input check failed."""
