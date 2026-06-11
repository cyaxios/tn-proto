"""C1 silo conftest — re-exports the hermetic fixture from `_shared/`.

Every C1 test gets `hermetic_machine` (or `hermetic_machine_with_vault`)
which guarantees the real user-home `~/AppData/Roaming/tn/` is not
touched, regardless of whether the SDK call would normally write there.
"""
from regression._shared.fixtures import (  # noqa: F401 — re-exported for pytest discovery
    assert_user_home_untouched,
    hermetic_machine,
    hermetic_machine_with_vault,
)
