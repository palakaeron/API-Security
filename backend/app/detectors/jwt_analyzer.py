"""JWT / token security analyzer.

OWASP API2:2023 (Broken Authentication — JWT sub-category)

Strategy
--------
Four sub-checks, each operating on a token obtained from the target's
authentication endpoint:

1. **Weak secret** — attempt to verify the token's HMAC-SHA256 signature
   against a small, hardcoded wordlist of commonly-misconfigured lab secrets.
   The wordlist is intentionally tiny, lab-scoped, and cannot be replaced by
   user input.  See ``_WEAK_SECRET_WORDLIST`` below.

2. **Algorithm ``none`` acceptance** — craft a modified token with
   ``"alg": "none"`` and an empty signature, then send it to a protected
   endpoint.  If the server returns 2xx the endpoint accepts unsigned tokens.

3. **Excessive expiry** — decode the ``exp`` claim (without verifying the
   signature) and flag tokens with an expiry more than 24 hours in the future.

4. **Missing claims** — flag tokens that lack ``iss``, ``aud``, or ``exp``
   claims, which are required by RFC 8725 §2.

Wordlist documentation (exit criterion 6)
------------------------------------------
``_WEAK_SECRET_WORDLIST`` contains **10 entries**.  Every entry is a known
synthetic lab secret that the vulnerable auth endpoint was deliberately
configured to use.  The list is:

  - 5 entries taken directly from the lab's own source (``lab-only-weak-secret``
    and obvious short variants a real misconfigured service might use)
  - 5 common short HMAC-SHA256 secrets seen in public CTF / tutorial JWT examples
    (``secret``, ``password``, ``changeme``, ``test``, ``jwt_secret``)

The wordlist is defined as a frozenset constant in this module.  It is not
read from config, not accepted as a parameter, and not extendable at runtime.
This satisfies the lab-scoped, non-user-supplied requirement in M4 exit
criterion 6.  Do not add production or real-world secret lists here.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import jwt as pyjwt

from app.detectors.base import DetectorResult, Evidence, OWASPCategory, Severity
from app.detectors.http_client import controlled_get, controlled_post_raw
from app.detectors.sanitiser import sanitise_headers
from app.security.target_allowlist import TargetPolicy

# ── Lab-scoped weak-secret wordlist (10 entries, hardcoded) ──────────────────
# DO NOT add production secrets, real wordlists, or user-supplied values here.
# These are synthetic values known to appear in intentionally-misconfigured
# lab / tutorial JWT configurations only.
_WEAK_SECRET_WORDLIST: frozenset[str] = frozenset(
    {
        # Direct lab secret (from lab/app/auth.py LAB_VULNERABLE_JWT_SECRET)
        "lab-only-weak-secret",
        # Short variants a misconfigured clone of the lab might use
        "lab-secret",
        "weak-secret",
        "lab-jwt-secret",
        "labsecret",
        # Common CTF / tutorial short HMAC secrets
        "secret",
        "password",
        "changeme",
        "test",
        "jwt_secret",
    }
)
_WORDLIST_SIZE = len(_WEAK_SECRET_WORDLIST)  # 10


def _decode_unverified(token: str) -> tuple[dict, dict]:
    """Decode header and payload without verifying the signature."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}, {}

    def _b64decode(segment: str) -> dict:
        pad = 4 - len(segment) % 4
        try:
            return json.loads(base64.urlsafe_b64decode(segment + "=" * (pad % 4)))
        except Exception:  # noqa: BLE001
            return {}

    return _b64decode(parts[0]), _b64decode(parts[1])


def _make_none_alg_token(original_token: str) -> str:
    """Return a modified token with alg=none and an empty signature."""
    header, payload = _decode_unverified(original_token)
    header["alg"] = "none"
    header["typ"] = "JWT"

    def _b64encode(obj: dict) -> str:
        encoded = base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":")).encode()
        )
        return encoded.rstrip(b"=").decode()

    return f"{_b64encode(header)}.{_b64encode(payload)}."


class JwtAnalyzer:
    """JWT / token security analyzer (OWASP API2:2023 — JWT sub-category).

    Checks a token obtained from the target's auth endpoint for weak secrets,
    algorithm-none acceptance, excessive expiry, and missing claims.
    """

    DETECTOR_ID = "jwt_analyzer"
    OWASP_CATEGORY = OWASPCategory.JWT
    SEVERITY = Severity.HIGH
    REMEDIATION_REF = (
        "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/ "
        "(see also RFC 8725 — JWT Best Current Practices)"
    )

    def run(
        self,
        base_url: str,
        policy: TargetPolicy,
        auth_path: str,
        login_payload: dict,
        protected_path: str,
        protected_path_param: str = "",
    ) -> DetectorResult:
        """Analyze JWT security on the target auth endpoint.

        :param base_url: Validated lab base URL.
        :param policy: Allowlist policy.
        :param auth_path: Path to the login endpoint, e.g. ``/vuln/auth/token``.
        :param login_payload: Credentials to obtain a token, e.g.
            ``{"username": "alice", "password": "synthetic-password"}``.
        :param protected_path: A path that requires authentication, used for
            the ``alg=none`` acceptance check.
        :param protected_path_param: Concrete value for ``{user_id}`` etc.
        :returns: ``DetectorResult`` summarising all JWT sub-checks.
        """
        findings: list[str] = []
        all_evidence: list[Evidence] = []
        max_confidence = 0.0

        # ── Step 0: Obtain a token ────────────────────────────────────────────
        auth_url = base_url.rstrip("/") + auth_path
        # The access token must be available transiently for cryptographic
        # analysis, but it must never enter an Evidence object.  The raw
        # helper sanitises headers while intentionally leaving the body raw;
        # consume only the token below and keep the stored evidence redacted.
        ts, th, tb = controlled_post_raw(
            auth_url, policy,
            headers={"Content-Type": "application/json"},
            json=login_payload,
        )
        all_evidence.append(
            Evidence(
                url=auth_url,
                method="POST",
                request_headers={"Content-Type": "application/json"},
                request_body={"username": login_payload.get("username", "")},  # password omitted
                response_status=ts,
                response_headers=sanitise_headers(th),
                response_body={},  # do not store the token in evidence
                context={"probe": "obtain_token", "detector": self.DETECTOR_ID},
            )
        )
        if ts != 200 or not isinstance(tb, dict) or "access_token" not in tb:
            return DetectorResult(
                detector_id=self.DETECTOR_ID,
                owasp_category=self.OWASP_CATEGORY,
                severity=Severity.INFO,
                confidence=0.0,
                vulnerable=False,
                evidence=all_evidence,
                title=f"JWT analyzer: could not obtain token from {auth_path} (HTTP {ts})",
                remediation_ref=self.REMEDIATION_REF,
                detail="Token acquisition failed; no JWT checks could be run.",
            )

        token: str = tb["access_token"]
        header, payload = _decode_unverified(token)

        # ── Sub-check 1: Weak secret ──────────────────────────────────────────
        cracked_secret: str | None = None
        alg = header.get("alg", "")
        if alg.startswith("HS"):
            for candidate in _WEAK_SECRET_WORDLIST:
                try:
                    pyjwt.decode(token, candidate, algorithms=[alg])
                    cracked_secret = candidate
                    break
                except pyjwt.PyJWTError:
                    continue

        all_evidence.append(
            Evidence(
                url=auth_url,
                method="POST",
                request_headers={},
                request_body={},
                response_status=ts,
                response_headers={},
                response_body={},
                context={
                    "probe": "weak_secret",
                    "algorithm": alg,
                    "cracked": cracked_secret is not None,
                    # Do NOT log the actual secret value — only whether it was found.
                    "wordlist_size": _WORDLIST_SIZE,
                    "detector": self.DETECTOR_ID,
                },
            )
        )
        if cracked_secret is not None:
            findings.append(
                f"weak secret: token HMAC secret is in the {_WORDLIST_SIZE}-entry "
                f"lab wordlist (algorithm={alg})"
            )
            max_confidence = max(max_confidence, 100.0)

        # ── Sub-check 2: Algorithm none acceptance ────────────────────────────
        none_token = _make_none_alg_token(token)
        prot_url = (
            base_url.rstrip("/")
            + protected_path.replace("{user_id}", protected_path_param)
        )
        none_headers = {"Authorization": f"Bearer {none_token}"}
        ns, nh, nb = controlled_get(prot_url, policy, headers=none_headers)
        all_evidence.append(
            Evidence(
                url=prot_url,
                method="GET",
                request_headers=sanitise_headers(none_headers),
                request_body=None,
                response_status=ns,
                response_headers=nh,
                response_body=nb,
                context={
                    "probe": "alg_none",
                    "expected": 401,
                    "actual": ns,
                    "detector": self.DETECTOR_ID,
                },
            )
        )
        if ns < 400:
            findings.append(
                f"algorithm-none acceptance: server accepted unsigned token "
                f"(HTTP {ns}) on {protected_path}"
            )
            max_confidence = max(max_confidence, 100.0)

        # ── Sub-check 3: Excessive expiry ─────────────────────────────────────
        exp = payload.get("exp")
        excessive_expiry = False
        expiry_hours: float | None = None
        if exp is not None:
            try:
                expiry_dt = datetime.fromtimestamp(int(exp), tz=UTC)
                delta = expiry_dt - datetime.now(UTC)
                expiry_hours = delta.total_seconds() / 3600
                excessive_expiry = expiry_hours > 24
            except (ValueError, OSError):
                pass

        all_evidence.append(
            Evidence(
                url=auth_url,
                method="POST",
                request_headers={},
                request_body={},
                response_status=ts,
                response_headers={},
                response_body={},
                context={
                    "probe": "expiry",
                    "exp_claim_present": exp is not None,
                    "expiry_hours": round(expiry_hours, 1) if expiry_hours is not None else None,
                    "excessive": excessive_expiry,
                    "detector": self.DETECTOR_ID,
                },
            )
        )
        if excessive_expiry:
            findings.append(
                f"excessive token expiry: {expiry_hours:.0f}h "
                f"(> 24h recommended maximum)"
            )
            max_confidence = max(max_confidence, 85.0)

        # ── Sub-check 4: Missing required claims ──────────────────────────────
        required_claims = {"exp", "iss", "aud", "sub"}
        missing_claims = required_claims - set(payload.keys())
        all_evidence.append(
            Evidence(
                url=auth_url,
                method="POST",
                request_headers={},
                request_body={},
                response_status=ts,
                response_headers={},
                response_body={},
                context={
                    "probe": "claims",
                    "missing_claims": sorted(missing_claims),
                    "present_claims": sorted(set(payload.keys())),
                    "detector": self.DETECTOR_ID,
                },
            )
        )
        if missing_claims:
            findings.append(
                f"missing JWT claims: {sorted(missing_claims)!r} "
                "(RFC 8725 §2 recommends exp, iss, aud, sub)"
            )
            max_confidence = max(max_confidence, 75.0)

        vulnerable = bool(findings)
        return DetectorResult(
            detector_id=self.DETECTOR_ID,
            owasp_category=self.OWASP_CATEGORY,
            severity=self.SEVERITY if vulnerable else Severity.INFO,
            confidence=max_confidence if vulnerable else 0.0,
            vulnerable=vulnerable,
            evidence=all_evidence,
            title=(
                f"JWT issues on {auth_path}: " + "; ".join(findings)
                if vulnerable
                else f"JWT security acceptable on {auth_path}"
            ),
            remediation_ref=self.REMEDIATION_REF,
            detail="\n".join(findings) if findings else "No JWT security issues detected.",
        )
