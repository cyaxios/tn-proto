"""Total an accepted Unity-located invoice edition and retain the signed report."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from providers.unity_edition_setup import configure, resolve


def run(workspace, *, url, volume):
    workspace = Path(workspace).expanduser().resolve()
    session, rules, administration = configure(workspace)
    with session:
        entry = resolve(workspace, session, rules, administration, url=url, volume=volume)
        work = session.workflow(receive="accounting", release="reporting")
        data = work.unseal(entry.publication, selection=entry.selection)
        total = sum(data.get("amounts"))
        data.set("total", total)
        data.select(["default"], fields={"default": ["total"]})
        report = work.seal(data)
        reports = workspace / "private/reports"
        reports.mkdir(exist_ok=True)
        with (reports / f"{report.id.removeprefix('sha256:')}.tn").open("xb") as output:
            report.write(output)
        print(total)
        return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--url", required=True)
    parser.add_argument("--volume", required=True)
    arguments = parser.parse_args()
    run(arguments.workspace, url=arguments.url, volume=arguments.volume)
