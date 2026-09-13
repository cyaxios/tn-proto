"""The agreed vocabulary exercises native objects and publication IO."""
import io
import pytest
import tn
from test_governed_application_session import POLICY


def test_verbs_and_registers(tmp_path):
    creation, release = tmp_path / "created.jsonl", tmp_path / "released.jsonl"
    with tn.Session(POLICY, registers=tn.ObjectRegisters(creation=creation, release=release)) as session:
        policy = session.policy("hello.message")
        source = session.create({"message": "hello", "extra": 1}, policy)
        assert creation.exists()
        session.configure_receive(use=tn.UseContext("hello", "read", "read"), decide=lambda c: c.writer == session.did)
        session.configure_release(use=tn.UseContext("hello", "send", "publish"), to="receiver", object_type="hello.message", decide=lambda _: True)
        work = session.workflow(receive="read", release="send")
        data = work.receive(source)
        state = data.inspect()
        data.set("message", "changed")
        assert state.groups["default"]["message"] == "hello"
        revision = data.revision
        with pytest.raises(ValueError):
            data.select(["default"], fields={"default": ["missing"]})
        assert data.revision == revision
        data.select(["default"], fields={"default": ["message"]})
        assert data.get() == {"message": "changed"}
        target = tmp_path / "message.tn"
        target.write_bytes(b"unchanged")
        with pytest.raises(ValueError, match="release"):
            data.write(target)
        assert target.read_bytes() == b"unchanged"
        with pytest.raises(ValueError):
            data.set(None, {}, group="tn.agents")
        publication = work.release(data)
        assert release.exists()
        data.write(target)
        restored = tn.GovernedObject.read(target)
        assert restored.forward() == publication.forward() == target.read_bytes()
        assert restored.inspect() == publication.inspect()
        stream = io.BytesIO()
        restored.write(stream)
        stream.seek(0)
        assert tn.GovernedObject.read(stream).forward() == restored.forward()
        verified = session.verify(restored.forward())
        view = session.governance(verified)
        admitted = view.accept(use=tn.UseContext("hello", "read", "read"), groups=["default"], decide=lambda _: True)
        opened = session.open(admitted, ["default"])
        assert opened.groups["default"]["message"] == "changed"


def test_binary_transport_short_writes_and_invalid_reads():
    with tn.Session(POLICY) as session:
        obj = session.create({"message": "hello"}, session.policy("hello.message"))
        class ShortWriter:
            def __init__(self): self.data = bytearray()
            def write(self, data):
                self.data.extend(data[:7])
                return min(7, len(data))
        out = ShortWriter()
        obj.write(out)
        assert bytes(out.data) == obj.forward()
        with pytest.raises(Exception):
            tn.GovernedObject.read(io.BytesIO(b"invalid"))


@pytest.mark.parametrize("behavior", ["zero", "too_large", "exception"])
def test_native_writer_rejects_invalid_python_stream_results(behavior):
    with tn.Session(POLICY) as session:
        data = session.create({"message": "hello"}, session.policy("hello.message"))
        publication = tn.GovernedObject.read(io.BytesIO(data.forward()))
        class Destination:
            def write(self, value):
                if behavior == "exception": raise LookupError("storage failure")
                return 0 if behavior == "zero" else len(value) + 1
        expected = LookupError if behavior == "exception" else OSError
        for obj in (data, publication):
            with pytest.raises(expected): obj.write(Destination())
