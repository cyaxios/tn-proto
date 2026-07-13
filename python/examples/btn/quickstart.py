"""Quickstart: seal a message, share a kit, read it back."""

from tn import btn

# A producer owns one group. It holds the secret; nothing is written anywhere.
p = btn.setup()

# Mint a reader kit and hand it to a reader.
alice_kit = p.mint()

# Seal a message. Everyone you've minted a kit for can open it.
ct = p.encrypt(b'{"order": "A100", "amount": 4999}')

# The reader opens it with just their kit - no server, no producer online.
alice = btn.subscribe(alice_kit)
print("alice reads:", alice.decrypt(ct))

# The producer can read its own log too.
print("producer reads:", p.decrypt(ct))
