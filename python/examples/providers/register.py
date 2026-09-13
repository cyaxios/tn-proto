"""Optional signed file registers and a Python event collector."""
from tn.governed import ObjectRegisters
from tn.providers import FileRegisters

def files(directory):
    return FileRegisters(ObjectRegisters(creation=directory / "creations.tn", release=directory / "releases.tn"))

class EventCollector:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)
