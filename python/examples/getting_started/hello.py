"""Run the README greeting walkthrough."""


def main():
    from pathlib import Path
    import tn

    session = tn.Session(Path(__file__).with_name("agents.md").read_text(encoding="utf-8"))
    policy = session.policy("hello.message")

    message = session.create({"message": "Hello, world!"}, policy)
    print(message.get("message"))

    message.set("message", "Hello again!")
    print(message.get("message"))

    publication = message.seal(
        purpose="send", to="local-reader", decide=lambda _: True
    )

    publication.write("greeting.tn")
    saved = tn.GovernedObject.read("greeting.tn")

    received = session.unseal(
        saved, purpose="read", decide=lambda _: True
    )
    print(received.get("message"))

    session.close()


if __name__ == "__main__":
    main()
