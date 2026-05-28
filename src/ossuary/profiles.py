"""Scan profile presets for ossuary.

Solo hunters repeatedly reconstruct nmap flag combinations from memory. A
preset locks in a tested set of flags behind a memorable name so repeatable
scans are trivial, and records *which* preset produced a given row so cruise
diffs (and post-hoc audits) can flag when an asset is re-scanned under a
different profile than it was discovered/fingerprinted with.

Each profile carries two distinct nmap argument strings:

    discover    — host-discovery (-sn family) arguments for `ossuary discover`
    fingerprint — service/version arguments for `ossuary fingerprint` / cruise

The two stages run different nmap modes, so a single flag string can't serve
both. Keeping them paired under one profile name means `--profile stealth`
means the same intent at both stages.

The DEFAULT_PROFILE reproduces ossuary's pre-profile behaviour exactly
(`-sn` for discovery, `-sV` for fingerprinting) so the feature is additive:
callers that pass no `--profile` get the historical flags and a recorded
profile name of "default".
"""

from __future__ import annotations

from typing import NamedTuple

DEFAULT_PROFILE = "default"


class Profile(NamedTuple):
    """A named pair of nmap argument strings for the two scan stages."""

    name: str
    discover: str
    fingerprint: str
    description: str


# Ordered so `list_profiles()` presents default first, then the documented
# stealth / aggressive / web trio from the post-v0.1 roadmap.
_PROFILES: dict[str, Profile] = {
    DEFAULT_PROFILE: Profile(
        name=DEFAULT_PROFILE,
        discover="-sn",
        fingerprint="-sV",
        description="ossuary's original flags — ping discovery, version detection",
    ),
    "stealth": Profile(
        name="stealth",
        # SYN-only, slow timing, skip host-discovery ping — bypasses basic IDS.
        discover="-sn -T2 -Pn",
        fingerprint="-sS -sV -T2 -Pn",
        description="slow & quiet: SYN-only, T2 timing, no ping (evades basic IDS)",
    ),
    "aggressive": Profile(
        name="aggressive",
        discover="-sn -T4",
        fingerprint="-sV -O -T4 --script=banner",
        description="loud & thorough: version + OS detection + service banners, T4",
    ),
    "web": Profile(
        name="web",
        discover="-sn",
        # Web-port-focused service detection at medium speed.
        fingerprint="-sV -p 80,443,8080,8443,8888 -T3",
        description="web-focused: version-detect common HTTP(S) ports at T3",
    ),
}


def profile_names() -> list[str]:
    """Return the available profile names in presentation order."""
    return list(_PROFILES)


def get_profile(name: str) -> Profile:
    """Look up a profile by name, raising a clear error for unknown names.

    The error lists the valid names so a typo at the CLI yields a usable
    message rather than a bare KeyError.
    """
    try:
        return _PROFILES[name]
    except KeyError:
        valid = ", ".join(_PROFILES)
        raise ValueError(
            f"unknown scan profile {name!r}; valid profiles: {valid}"
        ) from None


def list_profiles() -> list[Profile]:
    """Return all profiles in presentation order (for `--list-profiles`)."""
    return list(_PROFILES.values())
