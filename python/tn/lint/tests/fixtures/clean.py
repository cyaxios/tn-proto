"""Clean fixture: declared fields, no PII in event_type, no forbidden kwargs."""

import tn  # type: ignore[import-not-found]


def emit_order(order_id: str, amount: int, customer_id: str) -> None:
    tn.info(
        "order.created",
        order_id=order_id,
        amount=amount,
        customer_id=customer_id,
        correlation_id=f"order-{order_id}",
    )
