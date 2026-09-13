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

    def trusted_message(context):
        return (
            context.writer == session.did
            and len(context.policies) == 1
            and context.policies[0].matches_contract(policy)
        )

    publish_use = tn.UseContext("hello", "greeting", "publish")
    publication = message.seal(
        use=publish_use, to="local-reader",
        decide=lambda context: trusted_message(context)
        and context.use_context == publish_use
        and context.destination == "local-reader",
    )

    publication.write("greeting.tn")
    saved = tn.GovernedObject.read("greeting.tn")

    read_use = tn.UseContext("hello", "greeting", "read")
    received = session.unseal(
        saved, use=read_use,
        decide=lambda context: trusted_message(context)
        and context.use_context == read_use,
    )
    print(received.get("message"))

    session.close()


if __name__ == "__main__":
    main()
