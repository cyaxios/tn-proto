"""C2 silo conftest — re-exports the hermetic fixture from `_shared/`.

C2 tests the object-level handle surface (`t = tn.use(name)`) rather
than the module-level singleton (`tn.info(...)`). Both share the
hermetic fixture — TN_NO_LINK=1 by default, so no vault contact.
"""
from regression._shared.fixtures import (  # noqa: F401 — re-exported for pytest discovery
    assert_user_home_untouched,
    hermetic_machine,
    hermetic_machine_with_vault,
)
