"""The Python resolver feeds retained objects to the Rust lineage verifier."""

import pytest
from tn import Session, DatasetCatalog, PolicyDag, LineageVerifier

POLICY = """## data
### instruction
Calculate totals.
### use_for
Analysis.
### do_not_use_for
Individual disclosure.
### consequences
Review.
### on_violation_or_error
Refuse.
"""


def test_native_lineage_result_and_original_resolver_exception():
    with Session(POLICY) as session:
        data = session.create_obj({"total": 12}, session.policy("data"), object_type="data")
        parent = data.snapshot
        output = data.release(to="analytics", purpose="analysis", decide=lambda _: True)
        view = session.governance(output)
        seen = []

        def resolve(identity):
            seen.append(identity)
            assert identity == parent.id
            return session.governance(parent)

        proof = LineageVerifier().verify(view, DatasetCatalog(), PolicyDag(), resolve)
        assert set(proof.object_ids) == {parent.id, output.id}
        assert proof.source_object_ids == []
        assert seen == [parent.id]
        with pytest.raises(ValueError):
            LineageVerifier(max_objects=1).verify(view, DatasetCatalog(), PolicyDag(), resolve)
        with pytest.raises(ValueError):
            LineageVerifier().verify(view, DatasetCatalog(), PolicyDag(), lambda _: view)
        expected = LookupError("publication unavailable")

        def missing(identity):
            raise expected

        with pytest.raises(LookupError) as error:
            LineageVerifier().verify(view, DatasetCatalog(), PolicyDag(), missing)
        assert error.value is expected
        with pytest.raises(TypeError):
            LineageVerifier().verify(view, DatasetCatalog(), PolicyDag(), lambda _: {})
