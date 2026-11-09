"""Protocol-level errors. All derive from ProtocolError so callers can catch one type."""


class ProtocolError(Exception):
    """Base class for every protocol failure."""


class ParseError(ProtocolError):
    """Input is malformed: wrong version, unknown algorithm, bad length, trailing bytes."""


class VerificationError(ProtocolError):
    """A signature, expiry or authentication check failed."""


class DowngradeError(ProtocolError):
    """The peer offered or used a weaker mode than local policy allows (SR-6)."""


class ReplayError(ProtocolError):
    """A message, or a one-time prekey, was used twice (SR-10, SR-11)."""
