"""C5 silo conftest — re-exports the hermetic fixture from `_shared/`.

C5 simulates two "machines" in one pytest process: Alice (publisher)
and Frank (recipient). Both share the same hermetic environment
(TN_IDENTITY_DIR + TN_NO_LINK) but each gets its own tmpdir + ceremony,
with `tn.flush_and_close()` between them so the runtime singleton
isn't shared.
"""
from regression._shared.fixtures import (  # noqa: F401 — re-exported for pytest discovery
    assert_user_home_untouched,
    hermetic_machine,
    hermetic_machine_with_vault,
)
