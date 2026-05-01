"""R3 fixture: 'cvv' is forbidden_post_auth in the pci-cardholder pack."""

import tn  # type: ignore[import-not-found]


def emit_charge(cvv: str) -> None:
    tn.info("payment.charged", order_id="abc-123", amount=4900, cvv=cvv)
