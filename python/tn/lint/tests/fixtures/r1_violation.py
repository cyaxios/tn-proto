"""R1 fixture: PII (email) in the event_type literal."""

import tn  # type: ignore[import-not-found]


def emit_signup() -> None:
    tn.info("user.alice@example.com.signed_up", customer_id="abc-123")
