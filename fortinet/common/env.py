"""Environment variable compatibility helpers for Fortinet launchers."""

import os


def _candidate_names(name, aliases=(), legacy_aliases=()):
    """Yield preferred aliases, the FTNT spelling, then the original name."""
    seen = set()
    for candidate in aliases:
        if candidate not in seen:
            seen.add(candidate)
            yield candidate

    if name.startswith("FOS_"):
        ftnt_name = "FTNT_" + name[len("FOS_"):]
        if ftnt_name not in seen:
            seen.add(ftnt_name)
            yield ftnt_name

    if name not in seen:
        seen.add(name)
        yield name

    for candidate in legacy_aliases:
        if candidate not in seen:
            seen.add(candidate)
            yield candidate


def get_env(name, default=None, *, aliases=(), legacy_aliases=()):
    """Read an environment variable, preferring its FTNT spelling.

    ``aliases`` are checked first for renamed variables. ``legacy_aliases``
    are checked only after the canonical name to preserve older misspellings
    without allowing them to override a current spelling.
    """
    for candidate in _candidate_names(name, aliases, legacy_aliases):
        if candidate in os.environ:
            return os.environ[candidate]
    return default


def has_env(name, *, aliases=(), legacy_aliases=()):
    """Return whether any supported spelling is present in the environment."""
    return any(
        candidate in os.environ
        for candidate in _candidate_names(name, aliases, legacy_aliases)
    )
