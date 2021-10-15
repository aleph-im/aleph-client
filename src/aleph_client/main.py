"""This module only exists for backward compatibility and will be removed in a future release.
"""

import warnings

warnings.warn(
    "`aleph_client.main` is deprecated and will be removed. "
    "Use `aleph_client.synchronous` instead.",
    DeprecationWarning,
)

from .synchronous import *
