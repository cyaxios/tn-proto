from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any, cast

import pytest

from tn.read_policy import (
    ReadContext,
    ReadDecision,
    ReadRecordState,
    ReadRejectReason,
    ReadTrustPolicy,
)
from tn.read_trust import InMemoryReadTrustProvider


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / "tests/fixtures/trust/v1/read_policy_matrix.json"


def load_read_policy_cases() -> list[dict[str, Any]]:
    document = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert document["schema"] == "tn.trust-fixtures/v1"
    assert document["fixture"] == "read_policy_matrix"
    return cast(list[dict[str, Any]], document["cases"])


READ_POLICY_CASES = load_read_policy_cases()


def _context_for(case: dict[str, Any]) -> ReadContext:
    values = case["input"]["context"]
    local_device_did = values["local_device_did"]
    entries = {
        did: "local-device" if did == local_device_did else "verified-package"
        for did in values["trusted_writer_dids"]
    }
    return ReadContext(
        active=values["active"],
        local_log=values["local_log"],
        detached=values["detached"],
        writable=values["writable"],
        profile_sign=values["profile_sign"],
        profile_chain=values["profile_chain"],
        local_device_did=local_device_did,
        required_group=values["required_group"],
        trust_provider=InMemoryReadTrustProvider(entries),
    )


def resolve_case(case: dict[str, Any]) -> ReadTrustPolicy:
    values = case["input"]["policy"]
    return ReadTrustPolicy.resolve(
        verify=values["verify"],
        require_signature=values["require_signature"],
        allow_unauthenticated=values["allow_unauthenticated"],
        trusted_writers=values["trusted_writers"],
        allow_unknown_writers=values["allow_unknown_writers"],
        context=_context_for(case),
    )


def evaluate_case(case: dict[str, Any]) -> ReadDecision:
    values = case["input"]["record"]
    context = _context_for(case)
    policy_values = case["input"]["policy"]
    policy = ReadTrustPolicy.resolve(
        verify=policy_values["verify"],
        require_signature=policy_values["require_signature"],
        allow_unauthenticated=policy_values["allow_unauthenticated"],
        trusted_writers=policy_values["trusted_writers"],
        allow_unknown_writers=policy_values["allow_unknown_writers"],
        context=context,
    )
    record = ReadRecordState(
        record_valid=values["record_valid"],
        row_hash_present=values["row_hash_present"],
        row_hash_valid=values["row_hash_valid"],
        chain_valid=values["chain_valid"],
        signature_present=values["signature_present"],
        signature_valid=values["signature_valid"],
        writer_did=values["writer_did"],
        aad_valid=values["aad_valid"],
        recipient_groups=frozenset(values["recipient_groups"]),
    )
    return policy.evaluate(record, context)


@pytest.mark.parametrize("case", READ_POLICY_CASES, ids=lambda case: case["id"])
def test_read_policy_matrix(case: dict[str, Any]) -> None:
    expected = case["expected"]
    if expected.get("parameter_error"):
        with pytest.raises(ValueError):
            resolve_case(case)
        return

    policy = resolve_case(case)
    decision = evaluate_case(case)
    assert policy.mode == expected["resolved_mode"]
    assert decision.accepted is expected["accepted"]
    assert decision.reasons == expected.get("reasons", [])
    assert decision.writer_authenticated is expected["writer_authenticated"]
    assert decision.writer_authorized is expected["writer_authorized"]


def test_reject_reasons_have_frozen_wire_values_and_order() -> None:
    assert [reason.value for reason in ReadRejectReason] == [
        "record_invalid",
        "row_hash_invalid",
        "chain_invalid",
        "signature_required",
        "signature_invalid",
        "writer_untrusted",
        "aad_invalid",
        "not_a_recipient",
    ]


@pytest.mark.parametrize("verify", [None, 0, 1, "AUTO", "disabled", object()])
def test_verify_mode_rejects_values_outside_the_public_contract(verify: object) -> None:
    case = READ_POLICY_CASES[0]
    values = case["input"]["policy"]
    with pytest.raises(ValueError, match="verify"):
        ReadTrustPolicy.resolve(
            verify=verify,  # type: ignore[arg-type]
            require_signature=values["require_signature"],
            allow_unauthenticated=values["allow_unauthenticated"],
            trusted_writers=values["trusted_writers"],
            allow_unknown_writers=values["allow_unknown_writers"],
            context=_context_for(case),
        )


def test_disabled_rejects_even_an_empty_explicit_writer_override() -> None:
    case = next(item for item in READ_POLICY_CASES if item["id"] == "false_local_signed")
    with pytest.raises(ValueError, match="trusted_writers"):
        ReadTrustPolicy.resolve(
            verify=False,
            require_signature=None,
            allow_unauthenticated=None,
            trusted_writers=[],
            allow_unknown_writers=False,
            context=_context_for(case),
        )


def test_policy_is_frozen_and_snapshots_provider_trust() -> None:
    case = next(item for item in READ_POLICY_CASES if item["id"] == "auto_local_signed")
    entries = {
        case["input"]["record"]["writer_did"]: "local-device",
    }
    provider = InMemoryReadTrustProvider(entries)
    context = _context_for(case)
    context = ReadContext(
        active=context.active,
        local_log=context.local_log,
        detached=context.detached,
        writable=context.writable,
        profile_sign=context.profile_sign,
        profile_chain=context.profile_chain,
        local_device_did=context.local_device_did,
        required_group=context.required_group,
        trust_provider=provider,
    )
    policy = ReadTrustPolicy.resolve("auto", None, None, None, False, context)

    entries.clear()
    assert policy.trusted_writers == frozenset(
        {case["input"]["record"]["writer_did"]},
    )
    with pytest.raises(FrozenInstanceError):
        policy.mode = "skip"  # type: ignore[misc]


def test_multiple_failures_are_ordered_and_deduplicated() -> None:
    baseline = next(item for item in READ_POLICY_CASES if item["id"] == "auto_local_signed")
    context = _context_for(baseline)
    policy = ReadTrustPolicy.resolve("auto", None, None, None, False, context)
    record = ReadRecordState(
        record_valid=True,
        row_hash_present=True,
        row_hash_valid=False,
        chain_valid=False,
        signature_present=True,
        signature_valid=False,
        writer_did="did:key:z6Mkf1YtL1qR91LXM63W4mSmU18wCqFJCEGBWayXn7ykPuZ3",
        aad_valid=False,
        recipient_groups=frozenset(),
    )
    required_context = ReadContext(
        active=context.active,
        local_log=context.local_log,
        detached=context.detached,
        writable=context.writable,
        profile_sign=context.profile_sign,
        profile_chain=context.profile_chain,
        local_device_did=context.local_device_did,
        required_group="default",
        trust_provider=context.trust_provider,
    )

    decision = policy.evaluate(record, required_context)

    assert decision.reasons == [
        ReadRejectReason.ROW_HASH_INVALID,
        ReadRejectReason.CHAIN_INVALID,
        ReadRejectReason.SIGNATURE_INVALID,
        ReadRejectReason.WRITER_UNTRUSTED,
        ReadRejectReason.AAD_INVALID,
        ReadRejectReason.NOT_A_RECIPIENT,
    ]
    assert len(decision.reasons) == len(set(decision.reasons))
    assert decision.first_reason is ReadRejectReason.ROW_HASH_INVALID
    assert decision.writer_authenticated is False
    assert decision.writer_authorized is False


def test_allow_unauthenticated_never_accepts_a_present_invalid_signature() -> None:
    case = next(item for item in READ_POLICY_CASES if item["id"] == "explicit_foreign_unsigned")
    values = case["input"]["record"]
    context = _context_for(case)
    policy = resolve_case(case)
    record = ReadRecordState(
        record_valid=values["record_valid"],
        row_hash_present=values["row_hash_present"],
        row_hash_valid=values["row_hash_valid"],
        chain_valid=values["chain_valid"],
        signature_present=True,
        signature_valid=False,
        writer_did=values["writer_did"],
        aad_valid=values["aad_valid"],
        recipient_groups=frozenset(values["recipient_groups"]),
    )

    decision = policy.evaluate(record, context)

    assert decision.accepted is False
    assert decision.reasons == [ReadRejectReason.SIGNATURE_INVALID]
    assert decision.writer_authenticated is False
    assert decision.writer_authorized is False


def test_optional_hidden_group_never_implies_not_a_recipient() -> None:
    case = next(item for item in READ_POLICY_CASES if item["id"] == "auto_local_signed")
    values = case["input"]["record"]
    context = _context_for(case)
    record = ReadRecordState(
        record_valid=values["record_valid"],
        row_hash_present=values["row_hash_present"],
        row_hash_valid=values["row_hash_valid"],
        chain_valid=values["chain_valid"],
        signature_present=values["signature_present"],
        signature_valid=values["signature_valid"],
        writer_did=values["writer_did"],
        aad_valid=values["aad_valid"],
        recipient_groups=frozenset(),
    )

    decision = resolve_case(case).evaluate(record, context)

    assert decision.accepted is True
    assert ReadRejectReason.NOT_A_RECIPIENT not in decision.reasons


def test_detached_read_does_not_inherit_local_unsigned_profile() -> None:
    case = next(item for item in READ_POLICY_CASES if item["id"] == "auto_local_profile_unsigned")
    context = _context_for(case)
    detached_context = ReadContext(
        active=context.active,
        local_log=context.local_log,
        detached=True,
        writable=context.writable,
        profile_sign=context.profile_sign,
        profile_chain=context.profile_chain,
        local_device_did=context.local_device_did,
        required_group=context.required_group,
        trust_provider=context.trust_provider,
    )

    policy = ReadTrustPolicy.resolve("auto", None, None, None, False, detached_context)

    assert policy.require_signature is True
    assert policy.allow_unauthenticated is False


def test_detached_read_does_not_inherit_local_unchained_profile() -> None:
    case = next(item for item in READ_POLICY_CASES if item["id"] == "chain_disabled")
    values = case["input"]["record"]
    context = _context_for(case)
    detached_context = ReadContext(
        active=context.active,
        local_log=context.local_log,
        detached=True,
        writable=context.writable,
        profile_sign=context.profile_sign,
        profile_chain=context.profile_chain,
        local_device_did=context.local_device_did,
        required_group=context.required_group,
        trust_provider=context.trust_provider,
    )
    record = ReadRecordState(
        record_valid=values["record_valid"],
        row_hash_present=values["row_hash_present"],
        row_hash_valid=values["row_hash_valid"],
        chain_valid=values["chain_valid"],
        signature_present=values["signature_present"],
        signature_valid=values["signature_valid"],
        writer_did=values["writer_did"],
        aad_valid=values["aad_valid"],
        recipient_groups=frozenset(values["recipient_groups"]),
    )

    decision = resolve_case(case).evaluate(record, detached_context)

    assert decision.accepted is False
    assert decision.reasons == [ReadRejectReason.CHAIN_INVALID]
    assert decision.writer_authenticated is True
    assert decision.writer_authorized is False


@pytest.mark.parametrize(
    "case_id",
    [
        "auto_local_profile_unsigned",
        "explicit_foreign_unsigned",
        "row_hash_invalid",
        "chain_invalid",
        "row_then_chain_invalid",
        "disabled_ignores_signature",
    ],
)
def test_unauthenticated_or_integrity_failed_records_never_claim_authorization(
    case_id: str,
) -> None:
    case = next(item for item in READ_POLICY_CASES if item["id"] == case_id)
    assert evaluate_case(case).writer_authorized is False
