"""Weld a public, tamper-evident marker onto a sealed message (AAD).

The marker is authenticated into the ciphertext: the same marker must be given
to decrypt, and any change to it breaks the open. Use it to bind a governance /
policy string to the data it governs."""

from tn import btn

p = btn.setup()
alice = btn.subscribe(p.mint())

marker = b"governed:by=did:key:zAcme#policy=payments@1"
ct = p.encrypt(b'{"pan": "4111"}', aad=marker)

# Opening requires the exact marker - it is inseparable from the value.
print("with the right marker :", alice.decrypt(ct, aad=marker))
try:
    alice.decrypt(ct, aad=b"governed:by=someone-else")
except btn.NotEntitled:
    print("with a swapped marker : blocked")
