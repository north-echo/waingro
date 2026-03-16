"""Configuration for WAINGRO."""

from waingro import __version__
from waingro.models import Severity

VERSION = __version__
DEFAULT_MIN_SEVERITY = Severity.LOW
DEFAULT_FAIL_ON = Severity.HIGH
