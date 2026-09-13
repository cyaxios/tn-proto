"""Application storage for the book examples. This module is not TN SDK code."""
from dataclasses import dataclass
import io
import sqlite3
import tn


@dataclass(frozen=True)
class Saved:
    source: tn.GovernedObject
    publication: tn.GovernedObject
    effect: str


class Publications:
    """An accepted effect and its exact input/output publications share one commit."""
    def __init__(self, connection):
        self.db = connection
        self.db.execute("CREATE TABLE IF NOT EXISTS accepted (name TEXT PRIMARY KEY, source BLOB NOT NULL, output BLOB NOT NULL, effect TEXT NOT NULL)")
        self.db.commit()

    def get(self, name):
        row = self.db.execute("SELECT source, output, effect FROM accepted WHERE name=?", (name,)).fetchone()
        return None if row is None else Saved(tn.GovernedObject.read(io.BytesIO(row[0])), tn.GovernedObject.read(io.BytesIO(row[1])), row[2])

    def commit(self, name, source, output, effect):
        incoming, outgoing = source.forward(), output.forward()
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO accepted VALUES (?, ?, ?, ?)", (name, incoming, outgoing, effect))
            row = self.db.execute("SELECT source, output, effect FROM accepted WHERE name=?", (name,)).fetchone()
            if row[0] != incoming or row[2] != effect:
                raise ValueError("business identity already belongs to another request or effect")
        return tn.GovernedObject.read(io.BytesIO(row[1]))

    def replace(self, name, prior, output, effect):
        with self.db:
            changed = self.db.execute("UPDATE accepted SET source=output, output=?, effect=? WHERE name=? AND output=?", (output.forward(), effect, name, prior.forward())).rowcount
            if changed != 1:
                raise ValueError("accepted revision changed")
        return output


class Outbox:
    def __init__(self, connection):
        self.db = connection
        self.db.executescript("CREATE TABLE IF NOT EXISTS publication (name TEXT PRIMARY KEY, wire BLOB NOT NULL); CREATE TABLE IF NOT EXISTS pending (name TEXT PRIMARY KEY, wire BLOB NOT NULL);")

    def commit(self, name, publication):
        wire = publication.forward()
        with self.db:
            existing = self.db.execute("SELECT wire FROM publication WHERE name=?", (name,)).fetchone()
            if existing:
                if existing[0] != wire:
                    raise ValueError("publication identity conflicts")
                return
            self.db.execute("INSERT INTO publication VALUES (?, ?)", (name, wire))
            self.db.execute("INSERT INTO pending VALUES (?, ?)", (name, wire))

    def pending(self):
        import io
        return [(name, tn.GovernedObject.read(io.BytesIO(wire))) for name, wire in self.db.execute("SELECT name, wire FROM pending ORDER BY name")]

    def acknowledge(self, name):
        with self.db:
            self.db.execute("DELETE FROM pending WHERE name=?", (name,))


@dataclass(frozen=True)
class Approval:
    publication_id: str
    recipient: str


@dataclass(frozen=True)
class QuoteSelection:
    publication_ids: tuple[str, ...]
    instruments: tuple[str, ...]
    as_of: str


@dataclass(frozen=True)
class Edit:
    report_id: str
    account: str
    title: str


@dataclass(frozen=True)
class ObservationRequest:
    publication_id: str
    instrument: str
    as_of: str
