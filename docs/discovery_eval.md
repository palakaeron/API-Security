# M3 Discovery Evaluation

**Milestone:** M3 — API Discovery (OpenAPI import, Postman import, traffic capture, shadow/zombie diff)
**Date:** 2026-09-15
**Test run:** `pytest backend` — 39 passed, 0 failed (Python 3.12.1, pytest 8.3.4)

This document records the actual precision, recall, and false-positive measurements
for the M3 shadow/zombie discovery implementation. Numbers are derived directly from
the test run above; they are not estimates. This document is intended to seed the M9
evaluation section of the final write-up.

---

## 1. What was measured

The diff engine (`backend/app/discovery/diff.py`) compares two sets of endpoint rows in
the database:

- **Declared** rows: endpoints imported from an OpenAPI spec or Postman collection
  (`source IN ('spec', 'postman')`).
- **Traffic** rows: endpoints observed in captured HTTP traffic
  (`source='traffic'`, or an existing declared row updated with `seen_in_traffic=True`).

A **shadow endpoint** is flagged when a traffic-sourced row has no corresponding
declared row — the endpoint exists at runtime but is not documented.

A **zombie endpoint** is flagged when a declared row has `deprecated=True` AND
`seen_in_traffic=True` — the endpoint was explicitly retired in the contract but
remains reachable and is actively being used.

---

## 2. Ground truth — planted scenarios

Each test case in `backend/tests/test_discovery_diff.py` and `TestDiffEndpoint._seed`
constitutes one controlled scenario with a known ground truth. The table below lists
every distinct planted shadow or zombie instance across all test scenarios.

### Shadow scenarios (3 planted)

| # | Test | Planted shadow endpoint | Outcome |
|---|------|------------------------|---------|
| S1 | `test_shadow_endpoint_detected_when_in_traffic_but_not_in_spec` | `GET /internal/diagnostics` | ✅ Found |
| S2 | `test_shadow_and_zombie_can_coexist` | `POST /internal/hidden` | ✅ Found |
| S3 | `test_diff_endpoint_returns_shadow_and_zombie` (API-level) | `GET /internal/diagnostics` | ✅ Found |

### Zombie scenarios (3 planted)

| # | Test | Planted zombie endpoint | Outcome |
|---|------|------------------------|---------|
| Z1 | `test_zombie_endpoint_detected_when_deprecated_spec_endpoint_in_traffic` | `GET /v1/users/{id}` | ✅ Found |
| Z2 | `test_shadow_and_zombie_can_coexist` | `GET /v1/old` | ✅ Found |
| Z3 | `test_diff_endpoint_returns_shadow_and_zombie` (API-level) | `GET /v1/users/{user_id}` | ✅ Found |

### False-positive scenarios (4 explicit non-finding assertions)

Each scenario plants declared or deprecated endpoints that should **not** be flagged,
and asserts the diff output is empty.

| # | Test | Planted safe endpoints | Assertion |
|---|------|----------------------|-----------|
| FP1 | `test_empty_diff_when_all_traffic_is_declared` | `GET /orders/{id}`, `POST /orders` — declared AND seen in traffic (non-deprecated) | `shadow == []`, `zombie == []` |
| FP2 | `test_no_traffic_produces_empty_diff` | `GET /health` — declared, never seen in traffic | `shadow == []`, `zombie == []` |
| FP3 | `test_deprecated_endpoint_only_zombie_if_in_traffic` | `GET /v1/legacy` — declared deprecated, NOT in traffic | `zombie == []` |
| FP4 | `test_zombie_endpoint_detected` (cross-assertion) | `GET /v2/users/{id}` — non-deprecated, seen in traffic | `(GET, /v2/users/{id}) not in zombie` |

---

## 3. Metrics — shadow detection

All metrics are computed over the 3 planted shadow scenarios.

| Metric | Value | Formula |
|--------|-------|---------|
| Planted (TP + FN) | 3 | — |
| Found (TP) | 3 | — |
| Missed (FN) | 0 | planted − found |
| False alarms (FP) | 0 | declared non-deprecated endpoints incorrectly flagged as shadow |
| **Precision** | **1.00** | TP / (TP + FP) = 3 / 3 |
| **Recall** | **1.00** | TP / (TP + FN) = 3 / 3 |
| **F1** | **1.00** | 2 × (P × R) / (P + R) |

---

## 4. Metrics — zombie detection

All metrics are computed over the 3 planted zombie scenarios.

| Metric | Value | Formula |
|--------|-------|---------|
| Planted (TP + FN) | 3 | — |
| Found (TP) | 3 | — |
| Missed (FN) | 0 | planted − found |
| False alarms (FP) | 0 | non-deprecated declared endpoints incorrectly flagged as zombie |
| **Precision** | **1.00** | TP / (TP + FP) = 3 / 3 |
| **Recall** | **1.00** | TP / (TP + FN) = 3 / 3 |
| **F1** | **1.00** | 2 × (P × R) / (P + R) |

---

## 5. False-positive summary

4 explicit false-positive checks were exercised. All 4 passed — no declared
non-deprecated endpoint was incorrectly flagged as shadow or zombie in any test.

**Observed false-positive count: 0 / 4 checked cases**

---

## 6. Import parity (Postman ↔ OpenAPI round-trip)

Source: `backend/tests/test_postman_lab_roundtrip.py` — 7 tests, all pass.

| Service | Postman collection | OpenAPI spec | Endpoints | Parity |
|---------|-------------------|--------------|-----------|--------|
| Auth | `lab/postman/auth-collection.json` | `lab/openapi/services/auth.yaml` | 2 | ✅ Identical |
| Users | `lab/postman/users-collection.json` | `lab/openapi/services/users.yaml` | 6 | ✅ Identical |

Postman `{{variable}}` path segments are normalised to `{variable}` at parse time
(see `_normalise_postman_path` in `backend/app/discovery/parsers.py`), so paths from
both formats compare as equal. Nested Postman folder structures are recursively
flattened. Both properties are directly tested.

---

## 7. Methodology notes and limitations

### What these numbers do and do not mean

These precision/recall values are 1.00 by construction: the test scenarios were
designed together with the implementation. They demonstrate that the diff logic is
**correct for the cases it was written against**, not that it generalises to
arbitrary real-world APIs.

A meaningful evaluation against independent ground truth is planned for M9:

- 100+ controlled scenarios planted across all 7 lab services
- Shadow endpoints: the single planted `GET /internal/diagnostics` endpoint on the
  inventory service (port 8106) will be the primary real-traffic shadow target
- Zombie endpoints: `GET /v1/users/{user_id}` (inventory service, deprecated but
  reachable) will be the primary real-traffic zombie target
- Both will be tested via actual proxied HTTP traffic through the `TrafficRecorder`,
  not just in-process DB inserts

### Known constraints of M3 implementation

| Constraint | Impact |
|------------|--------|
| Path normalisation is heuristic (`_LOOKS_LIKE_ID` regex in `traffic.py`) | Variable segments in traffic-captured paths may not match spec path templates exactly if the heuristic mis-classifies a segment |
| `seen_in_traffic` is per-`(api_id, path, method)` row, not per-scan | Cannot distinguish between traffic from scan A vs. scan B within the same api_id; addressed in M5 when scan-scoped evidence is introduced |
| No real-time capture in M3 | The `TrafficRecorder` proxy exists but is not yet wired into a running scan job; `/discovery/traffic` is the current integration point |
| All 7 OpenAPI per-service specs validated against round-trip test (`test_all_seven_lab_specs_round_trip_exactly`) | 14 endpoints covered across auth, users, admin, payments, orders, inventory, graphql — confirmed identical on every service |

---

## 8. Full test counts (M3 close-out)

| Suite | Tests | Passed | Failed |
|-------|-------|--------|--------|
| `test_discovery_diff.py` | 20 | 20 | 0 |
| `test_postman_lab_roundtrip.py` | 7 | 7 | 0 |
| `test_lab_spec_roundtrip.py` | 1 | 1 | 0 |
| `test_discovery_parsers.py` | 3 | 3 | 0 |
| `test_discovery_persistence.py` | 1 | 1 | 0 |
| `test_health.py` | 1 | 1 | 0 |
| `test_target_allowlist.py` | 5 | 5 | 0 |
| **Total (backend)** | **39** | **39** | **0** |
| `lab/tests/test_lab.py` | 6 | 6 | 0 |
| **Grand total** | **45** | **45** | **0** |
