"""Run: python python/examples/providers/hello.py"""
from pathlib import Path
from tempfile import TemporaryDirectory
from tn.providers import Providers
import identity, keys, governance, register

def configured(registers=None):
    identities = identity.provision("analysis-service")
    actor = identities.resolve("analysis-service")
    grants = keys.provision(actor)
    contracts, request, workflow = governance.provision(actor)
    providers = Providers(identities, grants, contracts, registers=registers)
    session = providers.session(actor.application, workflows=[workflow])
    return providers, session, request

def calculate(providers, session, request):
    source = session.create({"value": 7}, providers.policy(request))
    work = session.workflow(receive="analysis", release="report")
    data = work.receive(source)
    data.set("value", data.get("value") + 1)
    return work.release(data)

if __name__ == "__main__":
    with TemporaryDirectory() as directory:
        providers, session, request = configured(register.files(Path(directory)))
        result = calculate(providers, session, request)
        print(session.receive(result, purpose="analysis").get("value"))
