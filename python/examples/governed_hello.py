"""Hello world with session setup and application code separated."""
import tn

POLICY = """## hello.message
### instruction
Read the message.
### use_for
Greeting.
### do_not_use_for
Other uses.
### consequences
Review.
### on_violation_or_error
Refuse.
"""


def configure(session):
    """Application startup: bind greeting to this writer and complete contract set."""
    writer = session.did
    expected = session.policy("hello.message")

    def admit(context):
        return (
            context.writer == writer
            and len(context.policies) == 1
            and context.policies[0].matches_contract(expected)
        )

    session.configure_receive(
        use=tn.UseContext("hello", "greeting", "read"), decide=admit
    )


def hello(session):
    return session.create(
        {"message": "Hello, world!"}, policy=session.policy("hello.message")
    )


def main():
    with tn.Session(POLICY) as session:
        configure(session)
        message = session.receive(hello(session), purpose="greeting")
        print(message.get("message"))


if __name__ == "__main__":
    main()
