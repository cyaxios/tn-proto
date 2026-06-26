"""R2 fixture: 'shoe_size' is not in tn.yaml or any extended pack."""

import tn  # type: ignore[import-not-found]


def emit_order(shoe_size: int) -> None:
    tn.info("order.created", order_id="abc-123", shoe_size=shoe_size)
