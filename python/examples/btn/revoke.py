"""Two readers, then cut one off. Revocation is forward-only."""

from tn import btn

p = btn.setup()
alice = btn.subscribe(p.mint())
bob_kit = p.mint()
bob = btn.subscribe(bob_kit)

# One sealed block, both readers open it.
first = p.encrypt(b'{"event": "login", "user": "A100"}')
print("alice reads first:", alice.decrypt(first))
print("bob reads first  :", bob.decrypt(first))

# Cut bob off. No re-encryption for alice - she is untouched.
p.revoke(bob_kit)

second = p.encrypt(b'{"event": "payout", "amount": 8800}')
print("alice reads second:", alice.decrypt(second))
try:
    bob.decrypt(second)
except btn.NotEntitled:
    print("bob reads second  : blocked")

# Forward-only: bob keeps whatever he could already read.
print("bob still reads first:", bob.decrypt(first))
