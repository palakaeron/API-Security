"""Synthetic lab fixtures. No real personal data or credentials belong here."""

USERS = {
    "alice": {
        "id": "alice",
        "email": "alice@example.test",
        "role": "user",
        "profile": {"display_name": "Alice Example", "support_pin": "1111"},
        "payment": {"account_ref": "pay_synthetic_alice", "balance_cents": 12500},
    },
    "bob": {
        "id": "bob",
        "email": "bob@example.test",
        "role": "user",
        "profile": {"display_name": "Bob Example", "support_pin": "2222"},
        "payment": {"account_ref": "pay_synthetic_bob", "balance_cents": 8600},
    },
    "admin": {
        "id": "admin",
        "email": "admin@example.test",
        "role": "admin",
        "profile": {"display_name": "Lab Administrator", "support_pin": "9999"},
        "payment": {"account_ref": "pay_synthetic_admin", "balance_cents": 0},
    },
}

ORDERS = {
    "ord-alice-001": {
        "id": "ord-alice-001",
        "owner_id": "alice",
        "status": "created",
        "total_cents": 2500,
    },
    "ord-bob-001": {
        "id": "ord-bob-001",
        "owner_id": "bob",
        "status": "created",
        "total_cents": 4800,
    },
}
