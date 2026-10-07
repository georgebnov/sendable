"""ESP detection package.

Checks consume `ESPProfile` to attribute findings to template chrome
versus user content. Detection runs once per audit via `detect(email)`.
"""

from ._detect import detect
from ._profile import ESPProfile, ProfileSpec

__all__ = ["ESPProfile", "ProfileSpec", "detect"]
