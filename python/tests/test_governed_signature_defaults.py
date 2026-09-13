"""Public introspection must report the same optional use value Rust accepts."""
import inspect

import pytest
from tn.governed import DataObject, Session


@pytest.mark.parametrize("method", [DataObject.release, Session.receive, Session.release])
def test_optional_use_default_is_none(method):
    use = inspect.signature(method).parameters["use"]
    assert use.kind is inspect.Parameter.KEYWORD_ONLY
    assert use.default is None
