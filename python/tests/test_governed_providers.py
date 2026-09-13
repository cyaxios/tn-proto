"""Run with python/examples/providers on PYTHONPATH against the installed wheel."""
from io import BytesIO
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples" / "providers"))
import pytest
from tn import governed as g
from tn.providers import (
    Providers, LocalIdentity, LocalKeys, PolicyRequest, CatalogEntry, CatalogRequest,
)
import identity, keys, governance, register, catalog
from hello import configured, calculate


def test_existing_identity_and_btn_material_can_be_loaded():
    from secrets import token_bytes
    from tn._native.btn import PublisherState
    from tn.providers import GroupCapability, KeySet
    seed = token_bytes(32)
    identity_provider = LocalIdentity.from_private_bytes("imported", seed)
    actor = identity_provider.resolve("imported")
    assert LocalIdentity.from_private_bytes("imported", seed).resolve("imported").did == actor.did
    with pytest.raises(ValueError): LocalIdentity.from_private_bytes("imported", b"short")
    capabilities = []
    for group in ["default", "tn.agents"]:
        state = PublisherState()
        kit = state.mint()
        index = token_bytes(32)
        capabilities.append(GroupCapability.btn_publisher(group, state.to_bytes(), [kit], index))
        assert GroupCapability.btn_reader(group, [kit], index).group == group
    assigned = KeySet(actor, capabilities)
    class Assigned:
        def resolve(self, identity): return assigned
    directory, request, workflow = governance.provision(actor)
    providers = Providers(identity_provider, Assigned(), directory)
    session = providers.session(actor.application, workflows=[workflow])
    assert calculate(providers, session, request).writer == actor.did
    with pytest.raises(ValueError): KeySet(actor, [capabilities[0]])
    with pytest.raises(ValueError): KeySet(actor, capabilities + [capabilities[0]])


def setup(registers=None, wrap=False):
    identities = identity.provision("analysis-service")
    actor = identities.resolve("analysis-service")
    grants = keys.provision(actor)
    directory, request, workflow = governance.provision(actor)

    class Adapter:
        def __init__(self, target):
            self.target = target
        def __getattr__(self, name):
            return getattr(self.target, name)

    providers = Providers(
        Adapter(identities) if wrap else identities,
        Adapter(grants) if wrap else grants,
        Adapter(directory) if wrap else directory,
        registers=registers,
    )
    return providers, actor, grants, directory, request, workflow


@pytest.mark.parametrize("wrap", [False, True])
def test_full_workflow_through_native_and_python_providers(wrap):
    events = register.EventCollector()
    providers, actor, _, _, request, workflow = setup(events, wrap)
    session = providers.session(actor.application, workflows=[workflow])
    output = calculate(providers, session, request)
    assert session.receive(output, purpose="analysis").get("value") == 8
    assert [e.action for e in events.events] == ["create", "release"]
    assert events.events[-1].publication.forward() == output.forward()


def test_same_provider_can_create_independent_sessions():
    providers, actor, _, _, request, workflow = setup()
    first = providers.session(actor.application, workflows=[workflow])
    second = providers.session(actor.application, workflows=[workflow])
    first.close()
    assert calculate(providers, second, request).writer == actor.did


def test_closing_session_during_provider_acceptance_stops_receipt():
    _, actor, grants, directory, request, workflow = setup()
    class Identity:
        def resolve(self, application): return actor
    class Decisions:
        session = None
        def policy(self, request): return directory.policy(request)
        def workflow(self, request): return directory.workflow(request)
        def accept(self, context):
            self.session.close()
            return True
        def attach(self, context): return directory.attach(context)
        def release(self, context): return directory.release(context)
    decisions = Decisions()
    providers = Providers(Identity(), grants, decisions)
    session = providers.session(actor.application, workflows=[workflow])
    decisions.session = session
    source = session.create({"value": 1}, providers.policy(request))
    with pytest.raises(ValueError, match="session is closed"):
        session.receive(source, purpose="analysis")


def test_wrong_application_identity_is_rejected():
    providers, actor, grants, directory, _, workflow = setup()
    class WrongIdentity:
        def resolve(self, application):
            return actor
    wrong = Providers(WrongIdentity(), grants, directory)
    with pytest.raises(ValueError, match="another application"):
        wrong.session("other-service", workflows=[])


def test_wrong_key_owner_is_rejected():
    _, actor, grants, directory, _, _ = setup()
    other = LocalIdentity("other-service")
    class WrongKeys:
        def resolve(self, identity):
            return grants.resolve(actor)
    with pytest.raises(ValueError, match="another identity"):
        Providers(other, WrongKeys(), directory).session("other-service", workflows=[])


def test_unassigned_identity_and_reader_only_creation():
    identities = LocalIdentity("reader")
    actor = identities.resolve("reader")
    grants = LocalKeys(["default"])
    directory, request, workflow = governance.provision(actor)
    providers = Providers(identities, grants, directory)
    with pytest.raises(ValueError, match="no keys assigned"):
        providers.session("reader", workflows=[])
    grants.assign(actor, read=["default"], publish=[])
    session = providers.session("reader", workflows=[workflow])
    with pytest.raises(g.NotAPublisher):
        session.create({"value": 1}, providers.policy(request))


def test_live_python_decision_and_strict_bool():
    _, actor, grants, directory, request, workflow = setup()
    class Identity:
        def resolve(self, application): return actor
    class Decisions:
        allow = True
        def policy(self, request): return directory.policy(request)
        def workflow(self, request): return directory.workflow(request)
        def accept(self, context): return self.allow and directory.accept(context)
        def attach(self, context): return directory.attach(context)
        def release(self, context): return self.allow and directory.release(context)
    decisions = Decisions()
    providers = Providers(Identity(), grants, decisions)
    session = providers.session(actor.application, workflows=[workflow])
    source = session.create({"value": 1}, providers.policy(request))
    decisions.allow = False
    with pytest.raises(g.UseDenied): session.receive(source, purpose="analysis")
    decisions.allow = True
    data = session.receive(source, purpose="analysis")
    decisions.allow = False
    with pytest.raises(g.UseDenied): data.release(purpose="report")
    decisions.accept = lambda ctx: 1
    with pytest.raises(ValueError, match="bool"): session.receive(source, purpose="analysis")


def test_python_policy_return_type_is_native():
    _, actor, grants, directory, request, _ = setup()
    class BadPolicy:
        def policy(self, request): return {"policy": "not a native contract"}
    with pytest.raises(ValueError, match="provider callback failed"):
        Providers(identity.provision(actor.application), grants, BadPolicy()).policy(request)


def test_register_failure_preserves_publication():
    class FailedRegister:
        def record(self, event): raise OSError("register unavailable")
    providers, session, request = configured(FailedRegister())
    source = session.create({"value": 1}, providers.policy(request))
    assert "register unavailable" in source.register_error
    assert g.GovernedObject.read(BytesIO(source.forward())).writer == session.did


def test_register_reentrant_access_fails_promptly():
    class Register:
        data = None
        def record(self, event):
            if self.data is not None: self.data.get("value")
    recorder = Register()
    providers, session, request = configured(recorder)
    source = session.create({"value": 1}, providers.policy(request))
    recorder.data = session.receive(source, purpose="analysis")
    output = recorder.data.release(purpose="report")
    assert output.writer == session.did
    assert "busy publishing" in recorder.data.register_error


def test_file_registers_are_written(tmp_path):
    providers, session, request = configured(register.files(tmp_path))
    calculate(providers, session, request)
    assert (tmp_path / "creations.tn").stat().st_size > 0
    assert (tmp_path / "releases.tn").stat().st_size > 0


def test_catalog_exact_selection_and_python_adapter():
    providers, actor, grants, directory, request, workflow = setup()
    session = providers.session(actor.application, workflows=[workflow])
    edition_catalog, query = catalog.provision(session, providers.policy(request), request.use_context, "values", "closing", directory)
    class Identity:
        def resolve(self, application): return actor
    class Catalog:
        def resolve(self, request): return edition_catalog.resolve(request)
    configured_catalog = Providers(Identity(), grants, directory, catalog=Catalog())
    entry = configured_catalog.resolve(query)
    data = session.receive(entry.publication, purpose="analysis", selection=entry.selection)
    assert data.get("value") == 7
    with pytest.raises(ValueError):
        configured_catalog.resolve(CatalogRequest(query.dataset, "missing", query.use_context))
    class WrongSource:
        def resolve(self, request):
            different = session.create({"value": 9}, providers.policy(PolicyRequest("example.value", query.use_context)))
            return CatalogEntry(g.GovernedObject.read(BytesIO(different.forward())), entry.selection)
    with pytest.raises(ValueError, match="catalog result differs"):
        Providers(Identity(), grants, directory, catalog=WrongSource()).resolve(query)


@pytest.mark.parametrize("case", ["policy", "catalog", "empty_groups", "duplicate_groups", "governance_group", "empty_workflow", "destination", "duplicate_routes", "foreign_output"])
def test_typed_requests_reject_invalid_configuration_in_rust(case):
    from tn.providers import WorkflowRequest, WorkflowPolicy, InputRule
    use = g.UseContext("app", "analysis", "calculate")
    with pytest.raises(ValueError):
        if case == "policy": PolicyRequest("", use)
        elif case == "catalog": CatalogRequest("values", "", use)
        elif case == "empty_groups": InputRule([])
        elif case == "duplicate_groups": InputRule(["default", "default"])
        elif case == "governance_group": InputRule(["tn.agents"])
        elif case == "empty_workflow": WorkflowPolicy([], "result", "reporting")
        elif case == "destination": WorkflowPolicy([InputRule(["default"])], "result", "")
        elif case == "duplicate_routes": WorkflowPolicy([InputRule(["default"]), InputRule(["default"])], "result", "reporting")
        elif case == "foreign_output": WorkflowRequest(use, g.UseContext("other", "report", "publish"))


def test_every_documented_provider_class_and_member_is_exposed_by_pyo3():
    import ast
    import inspect
    import tn.providers as api
    from tn._native import governed as native
    reference = Path(api.__file__).with_suffix(".pyi")
    tree = ast.parse(reference.read_text(encoding="utf-8"))
    for declaration in tree.body:
        if not isinstance(declaration, ast.ClassDef): continue
        if any(isinstance(base, ast.Name) and base.id == "Protocol" for base in declaration.bases): continue
        exported = getattr(api, declaration.name)
        assert exported is getattr(native, declaration.name), declaration.name
        for member in declaration.body:
            if not isinstance(member, ast.FunctionDef): continue
            actual = exported if member.name == "__init__" else getattr(exported, member.name)
            if any(isinstance(d, ast.Name) and d.id == "property" for d in member.decorator_list):
                assert isinstance(actual, property) or hasattr(actual, "__get__")
                continue
            expected = [arg.arg for arg in member.args.args + member.args.kwonlyargs if arg.arg not in ("self", "cls")]
            found = [name for name in inspect.signature(actual).parameters if name not in ("self", "cls")]
            assert found == expected, (declaration.name, member.name, found, expected)
