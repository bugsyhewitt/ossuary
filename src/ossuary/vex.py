"""VEX (Vulnerability Exploitability eXchange) suppression for ossuary.

A VEX document is the triage artefact that records, per CVE, *whether a
vulnerability actually applies* to a given product — "we ship this library but
the vulnerable code path is unreachable here," or "we patched it in this build."
The OpenVEX specification (https://github.com/openvex/spec) is the open JSON
shape for that statement: a list of statements, each declaring a
``vulnerability`` (the CVE), a ``status`` (one of ``not_affected``,
``affected``, ``fixed``, ``under_investigation``), and optionally the
``products`` the statement applies to.

Why a hunter wants this in ossuary: after a `match-cves` pass a large engagement
carries hundreds of CVE findings, and triage inevitably marks a chunk of them as
*not actually exploitable here* (the service version is a false-positive match,
the vulnerable feature is disabled, the box was patched out-of-band). Re-running
a scan re-discovers those same CVEs every time, so without a record of "already
ruled out," the noise comes back on every cruise. A VEX document is the standard,
portable way to capture those rulings — and feeding it into ossuary's read
surfaces lets a hunter *suppress* the ruled-out findings from every report
without deleting the underlying rows (the evidence stays in the DB; the VEX just
hides what's been triaged away).

Suppression semantics: a finding is suppressed when a VEX statement covers its
CVE with a status of ``not_affected`` or ``fixed`` — the two statuses that mean
"this is not a live issue here." ``affected`` and ``under_investigation`` leave
the finding visible (they're explicitly *not* a clearance). A statement with no
``products`` applies to every finding for that CVE (a blanket ruling); a
statement that lists ``products`` only suppresses findings whose host/port/CPE
matches one of the listed product identifiers, so a per-host ruling doesn't
silence the same CVE on a different box.

This module only *parses* a VEX document into a fast-lookup
:class:`VexSuppressions` index. The suppression is applied at the finding level
inside ``dump.build_state`` (like every other ossuary read-surface filter), so it
composes with `--tag`, the actionability filters, and priority ordering, and
flows uniformly into `dump`'s json / csv / markdown / html / sarif / jira
formats. No network calls, no new schema, no new dependencies.
"""

from __future__ import annotations

import json
from pathlib import Path

# The two OpenVEX statuses that clear a finding (mark it not a live issue here).
# `affected` and `under_investigation` deliberately do NOT suppress.
SUPPRESSING_STATUSES = frozenset({"not_affected", "fixed"})

# Every status the OpenVEX spec defines, used to validate a statement's status.
VALID_STATUSES = frozenset(
    {"not_affected", "affected", "fixed", "under_investigation"}
)


class VexError(ValueError):
    """Raised when a VEX document is malformed or unreadable."""


class VexSuppressions:
    """A fast-lookup index of the CVE rulings parsed from a VEX document.

    Built by :func:`load`. Two kinds of suppression are tracked:

      * *blanket* — a suppressing statement with no ``products``; the CVE is
        suppressed wherever it appears.
      * *scoped* — a suppressing statement that lists ``products``; the CVE is
        suppressed only on findings whose location (ip, ``ip:proto/port``, or
        CPE) matches one of the listed product identifiers.

    Use :meth:`is_suppressed` to test a single finding. The class is read-only
    after construction.
    """

    def __init__(
        self,
        blanket: set[str],
        scoped: dict[str, set[str]],
    ) -> None:
        # CVE ids cleared everywhere.
        self._blanket = blanket
        # CVE id -> set of product identifiers it is cleared for.
        self._scoped = scoped

    def __len__(self) -> int:
        """Number of distinct CVE ids carrying any suppressing statement."""
        return len(self._blanket | set(self._scoped))

    @property
    def blanket_cves(self) -> frozenset[str]:
        """CVE ids suppressed wherever they appear (no product scope)."""
        return frozenset(self._blanket)

    @property
    def scoped_cves(self) -> frozenset[str]:
        """CVE ids suppressed only for specific product identifiers."""
        return frozenset(self._scoped)

    def is_suppressed(
        self,
        cve_id: str | None,
        *,
        identifiers: set[str] | None = None,
    ) -> bool:
        """Return True when a finding for ``cve_id`` should be suppressed.

        ``cve_id`` is matched case-insensitively (VEX documents and OSV/NVD
        differ on CVE-id casing). A blanket ruling suppresses regardless of
        location. A scoped ruling suppresses only when one of the finding's
        ``identifiers`` (its ip, ``ip:proto/port`` location, and/or CPE) matches
        a product identifier the statement listed.
        """
        if not cve_id:
            return False
        key = cve_id.strip().upper()
        if key in self._blanket:
            return True
        products = self._scoped.get(key)
        if not products:
            return False
        if not identifiers:
            return False
        return bool(products & identifiers)


def _product_identifiers(product: dict | str) -> set[str]:
    """Extract the matchable identifier strings from one OpenVEX product entry.

    An OpenVEX product is normally an object with an ``@id`` (and optionally an
    ``identifiers`` map of {scheme: value} — e.g. a CPE or PURL). For ossuary's
    local-network use we match a finding against any of: the asset ip, the
    ``ip:proto/port`` service location, or the service CPE — so we collect every
    string-y identifier the product carries and let the caller test membership.
    A bare string product is taken as a single identifier.
    """
    if isinstance(product, str):
        text = product.strip()
        return {text} if text else set()
    ids: set[str] = set()
    pid = product.get("@id")
    if isinstance(pid, str) and pid.strip():
        ids.add(pid.strip())
    identifiers = product.get("identifiers")
    if isinstance(identifiers, dict):
        for value in identifiers.values():
            if isinstance(value, str) and value.strip():
                ids.add(value.strip())
    return ids


def parse(document: dict) -> VexSuppressions:
    """Parse an in-memory OpenVEX document dict into a :class:`VexSuppressions`.

    Raises :class:`VexError` if the document is not a dict, has no
    ``statements`` list, or contains a statement with an unrecognised status or
    no vulnerability. Statements whose status is not suppressing are accepted but
    contribute no suppression (they record "still affected / investigating").
    """
    if not isinstance(document, dict):
        raise VexError("VEX document must be a JSON object")
    statements = document.get("statements")
    if not isinstance(statements, list):
        raise VexError("VEX document must carry a 'statements' array")

    blanket: set[str] = set()
    scoped: dict[str, set[str]] = {}

    for idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            raise VexError(f"statement #{idx} is not an object")
        cve_id = _statement_vulnerability(stmt, idx)
        status = stmt.get("status")
        if status is None:
            raise VexError(f"statement #{idx} ({cve_id}) has no 'status'")
        if status not in VALID_STATUSES:
            raise VexError(
                f"statement #{idx} ({cve_id}) has unknown status {status!r} "
                f"(expected one of {', '.join(sorted(VALID_STATUSES))})"
            )
        if status not in SUPPRESSING_STATUSES:
            # affected / under_investigation: a recorded ruling, but not a
            # clearance — leave the finding visible.
            continue

        key = cve_id.strip().upper()
        products = stmt.get("products")
        if not products:
            # Blanket clearance: the CVE is ruled out wherever it appears. A
            # blanket ruling supersedes any prior scoped ruling for the CVE.
            blanket.add(key)
            scoped.pop(key, None)
            continue
        if key in blanket:
            # Already cleared everywhere; a narrower scope adds nothing.
            continue
        if not isinstance(products, list):
            raise VexError(
                f"statement #{idx} ({cve_id}) 'products' must be an array"
            )
        ids: set[str] = set()
        for product in products:
            ids |= _product_identifiers(product)
        if ids:
            scoped.setdefault(key, set()).update(ids)
        # A products list that yields no usable identifiers is treated as a
        # no-op scoped ruling (it clears nothing) rather than an error, so a
        # sparsely-populated product entry doesn't reject the whole document.

    return VexSuppressions(blanket, scoped)


def _statement_vulnerability(stmt: dict, idx: int) -> str:
    """Extract the CVE id from a statement's ``vulnerability`` field.

    OpenVEX allows ``vulnerability`` to be either a bare string id or an object
    carrying a ``name`` (the CVE id) — both shapes are accepted. Raises
    :class:`VexError` when neither yields an id.
    """
    vuln = stmt.get("vulnerability")
    if isinstance(vuln, str) and vuln.strip():
        return vuln.strip()
    if isinstance(vuln, dict):
        name = vuln.get("name") or vuln.get("@id")
        if isinstance(name, str) and name.strip():
            return name.strip()
    raise VexError(f"statement #{idx} has no usable 'vulnerability' id")


def load(path: str | Path) -> VexSuppressions:
    """Read and parse a VEX document from a JSON file path.

    Raises :class:`VexError` if the file is missing or not valid JSON, or if the
    parsed document is not a well-formed VEX document (see :func:`parse`).
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise VexError(f"VEX file not found: {path}") from exc
    except OSError as exc:
        raise VexError(f"could not read VEX file {path}: {exc}") from exc
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise VexError(f"VEX file {path} is not valid JSON: {exc}") from exc
    return parse(document)
