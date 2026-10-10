"""SQLite-backed, target- and session-scoped synthetic memory service."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Callable


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class MemoryStore:
    def __init__(self, connect: Callable[[], Any]):
        self._connect = connect

    def list(self, target_id: str, session_id: str) -> list[dict[str, Any]]:
        now = utcnow()
        with self._connect() as con:
            rows = con.execute(
                "SELECT id,memory_key,value_json,provenance,trust_label,expires_at,created_at,modified_at,version FROM memory_records WHERE target_id=? AND session_id=? AND deleted=0 AND (expires_at IS NULL OR expires_at>?) ORDER BY memory_key",
                (target_id, session_id, now),
            ).fetchall()
        return [{**dict(row), "value": json.loads(row["value_json"])} for row in rows]

    def read(self, target_id: str, session_id: str, key: str) -> dict[str, Any] | None:
        return next((entry for entry in self.list(target_id, session_id) if entry["memory_key"] == key), None)

    def write(self, target_id: str, session_id: str, key: str, value: Any, provenance: str, trust_label: str = "untrusted", expires_at: str | None = None) -> dict[str, Any]:
        if trust_label not in {"trusted", "untrusted", "system-managed"}:
            raise ValueError("trust_label must be trusted, untrusted, or system-managed")
        if not key or len(key) > 160 or len(provenance) > 1000:
            raise ValueError("Memory key or provenance is invalid or too long")
        encoded = json.dumps(value, ensure_ascii=False)
        if len(encoded) > 16_000:
            raise ValueError("Memory value exceeds the 16 KB limit")
        now = utcnow()
        with self._connect() as con:
            row = con.execute("SELECT * FROM memory_records WHERE target_id=? AND session_id=? AND memory_key=?", (target_id, session_id, key)).fetchone()
            if row:
                version = int(row["version"]) + 1
                con.execute("INSERT INTO memory_versions(id,record_id,version,value_json,provenance,trust_label,created_at) VALUES(?,?,?,?,?,?,?)",(str(uuid.uuid4()),row["id"],row["version"],row["value_json"],row["provenance"],row["trust_label"],now))
                con.execute("UPDATE memory_records SET value_json=?,provenance=?,trust_label=?,expires_at=?,modified_at=?,version=?,deleted=0 WHERE id=?",(encoded,provenance,trust_label,expires_at,now,version,row["id"]))
                record_id = row["id"]
            else:
                record_id = str(uuid.uuid4())
                version = 1
                con.execute("INSERT INTO memory_records(id,target_id,session_id,memory_key,value_json,provenance,trust_label,expires_at,created_at,modified_at,version,deleted) VALUES(?,?,?,?,?,?,?,?,?,?,1,0)",(record_id,target_id,session_id,key,encoded,provenance,trust_label,expires_at,now,now))
            con.execute("INSERT INTO memory_versions(id,record_id,version,value_json,provenance,trust_label,created_at) VALUES(?,?,?,?,?,?,?)",(str(uuid.uuid4()),record_id,version,encoded,provenance,trust_label,now))
            saved = con.execute("SELECT * FROM memory_records WHERE id=?", (record_id,)).fetchone()
        return {**dict(saved), "value": json.loads(saved["value_json"])}

    def snapshot(self, target_id: str, session_id: str, label: str = "Manual snapshot") -> dict[str, Any]:
        records = self.list(target_id, session_id)
        snapshot_id = str(uuid.uuid4())
        created = utcnow()
        with self._connect() as con:
            con.execute("INSERT INTO memory_snapshots(id,target_id,session_id,label,records_json,created_at) VALUES(?,?,?,?,?,?)",(snapshot_id,target_id,session_id,label,json.dumps(records,ensure_ascii=False),created))
        return {"id":snapshot_id,"target_id":target_id,"session_id":session_id,"label":label,"record_count":len(records),"created_at":created,"records":records}

    def restore(self, snapshot_id: str) -> dict[str, Any]:
        with self._connect() as con:
            snapshot = con.execute("SELECT * FROM memory_snapshots WHERE id=?", (snapshot_id,)).fetchone()
            if not snapshot:
                raise KeyError("Memory snapshot not found")
            target_id, session_id = snapshot["target_id"], snapshot["session_id"]
            records = json.loads(snapshot["records_json"])
            con.execute("UPDATE memory_records SET deleted=1,modified_at=? WHERE target_id=? AND session_id=?",(utcnow(),target_id,session_id))
        for record in records:
            self.write(target_id,session_id,record["memory_key"],record["value"],f"restore:{snapshot_id}:{record['provenance']}",record["trust_label"],record.get("expires_at"))
        return {"snapshot_id":snapshot_id,"target_id":target_id,"session_id":session_id,"restored_count":len(records),"records":self.list(target_id,session_id)}

    def reset(self, target_id: str, session_id: str) -> dict[str, Any]:
        now = utcnow()
        with self._connect() as con:
            changed = con.execute("UPDATE memory_records SET deleted=1,modified_at=?,version=version+1 WHERE target_id=? AND session_id=? AND deleted=0",(now,target_id,session_id)).rowcount
        return {"target_id":target_id,"session_id":session_id,"deleted_count":changed}

    def history(self, target_id: str, session_id: str, key: str) -> list[dict[str, Any]]:
        with self._connect() as con:
            row = con.execute("SELECT id FROM memory_records WHERE target_id=? AND session_id=? AND memory_key=?",(target_id,session_id,key)).fetchone()
            if not row:
                return []
            versions = con.execute("SELECT version,value_json,provenance,trust_label,created_at FROM memory_versions WHERE record_id=? ORDER BY version",(row["id"],)).fetchall()
        return [{**dict(item),"value":json.loads(item["value_json"])} for item in versions]

    def snapshots(self, target_id: str, session_id: str) -> list[dict[str, Any]]:
        with self._connect() as con:
            rows = con.execute("SELECT id,label,created_at,records_json FROM memory_snapshots WHERE target_id=? AND session_id=? ORDER BY created_at DESC",(target_id,session_id)).fetchall()
        return [{"id":row["id"],"label":row["label"],"created_at":row["created_at"],"record_count":len(json.loads(row["records_json"]))} for row in rows]
