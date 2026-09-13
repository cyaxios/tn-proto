"""The governed application operations are identical for BTN and JWE."""
import argparse
from pathlib import Path
import tn
from configuration import configure


def publish(directory, session, policy):
    source = session.create({"message": "Hello, world!"}, policy, group="messages")
    if source.register_error:
        raise RuntimeError(source.register_error)
    work = session.workflow(receive="greeting", release="delivery")
    data = work.receive(source)
    result = work.release(data)
    if data.register_error:
        raise RuntimeError(data.register_error)
    result.write(directory / "hello.tn")
    print("Published hello.tn")


def read(directory, session):
    publication = tn.GovernedObject.read(directory / "hello.tn")
    data = session.receive(publication, purpose="greeting")
    print(data.get("message"))


def main(cipher):
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("operation", choices=["publish", "read"])
    args = parser.parse_args()
    session, policy = configure(args.directory, cipher)
    with session:
        if args.operation == "publish":
            publish(args.directory, session, policy)
        else:
            read(args.directory, session)
