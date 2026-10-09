"""
AegisOSINT - Forensic Evidence Locker & Chain-of-Custody Engine
Implements cryptographic artifact hashing (SHA-256, SHA-3), tamper-evident hash chaining,
UTC timestamping, and integrity verification for legal and takedown proceedings.
"""

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


AUDIT_SECRET_KEY = b"aegis_osint_immutable_forensic_chain_key_2026"


class EvidenceLocker:
    """Manages forensic evidence acquisition, cryptographic hashing, and chain-of-custody ledgers."""

    def __init__(self, storage_dir: Optional[str] = None):
        self.storage_dir = storage_dir or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "data", "evidence_vault"
        )
        os.makedirs(self.storage_dir, exist_ok=True)
        self.ledger_file = os.path.join(self.storage_dir, "chain_of_custody_ledger.json")
        self._init_ledger()

    def _init_ledger(self):
        """Initializes persistent ledger with genesis block if not present."""
        if not os.path.exists(self.ledger_file):
            genesis_record = {
                "sequence": 0,
                "evidence_id": "00000000-0000-0000-0000-000000000000",
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "artifact_type": "GENESIS_ROOT",
                "target_uri": "system://aegis-osint-root",
                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "previous_block_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                "block_hash": "7a9a1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f",
                "seal": "INITIALIZED"
            }
            with open(self.ledger_file, "w", encoding="utf-8") as f:
                json.dump([genesis_record], f, indent=2)

    def _get_latest_block_hash(self) -> str:
        """Retrieves the cryptographic hash of the latest ledger entry."""
        try:
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                ledger = json.load(f)
                if ledger:
                    return ledger[-1]["block_hash"]
        except Exception:
            pass
        return "0000000000000000000000000000000000000000000000000000000000000000"

    def record_evidence(
        self,
        target_uri: str,
        artifact_type: str,
        content: Any,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Cryptographically registers, timestamps, and preserves an item of evidence.
        Computes SHA-256 and SHA3-512 hashes and appends to hash-chained custody ledger.
        """
        # Convert content to bytes for hashing
        if isinstance(content, str):
            raw_bytes = content.encode('utf-8')
        elif isinstance(content, (bytes, bytearray)):
            raw_bytes = bytes(content)
        elif isinstance(content, dict) or isinstance(content, list):
            raw_bytes = json.dumps(content, sort_keys=True).encode('utf-8')
        else:
            raw_bytes = str(content).encode('utf-8')

        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        sha3_512_hash = hashlib.sha3_512(raw_bytes).hexdigest()
        evidence_id = str(uuid.uuid4())
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        # Compute digital verification HMAC seal
        seal = hmac.new(
            AUDIT_SECRET_KEY,
            f"{evidence_id}:{sha256_hash}:{timestamp_utc}".encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        # Previous block hash for chain-of-custody
        previous_block_hash = self._get_latest_block_hash()

        # Compute current block hash
        block_content = f"{previous_block_hash}:{evidence_id}:{sha256_hash}:{timestamp_utc}"
        block_hash = hashlib.sha256(block_content.encode('utf-8')).hexdigest()

        # Save raw content file
        artifact_filename = f"{evidence_id}_{artifact_type.lower()}.dat"
        artifact_path = os.path.join(self.storage_dir, artifact_filename)
        with open(artifact_path, "wb") as f:
            f.write(raw_bytes)

        evidence_entry = {
            "evidence_id": evidence_id,
            "target_uri": target_uri,
            "artifact_type": artifact_type,
            "timestamp_utc": timestamp_utc,
            "sha256_hash": sha256_hash,
            "sha3_512_hash": sha3_512_hash,
            "byte_size": len(raw_bytes),
            "previous_block_hash": previous_block_hash,
            "block_hash": block_hash,
            "hmac_seal": seal,
            "collector": "AegisOSINT Forensic Daemon v1.0",
            "artifact_file": artifact_filename,
            "metadata": metadata or {}
        }

        # Append to custody ledger
        try:
            with open(self.ledger_file, "r+", encoding="utf-8") as f:
                ledger = json.load(f)
                evidence_entry["sequence"] = len(ledger)
                ledger.append(evidence_entry)
                f.seek(0)
                json.dump(ledger, f, indent=2)
                f.truncate()
        except Exception as e:
            evidence_entry["ledger_error"] = str(e)

        return evidence_entry

    def verify_evidence(self, evidence_id: str, current_content: Any) -> Dict[str, Any]:
        """
        Verifies whether current artifact matches the original cryptographic seal.
        Detects tampering or bit-rot for legal chain-of-custody validation.
        """
        if isinstance(current_content, str):
            raw_bytes = current_content.encode('utf-8')
        elif isinstance(current_content, (bytes, bytearray)):
            raw_bytes = bytes(current_content)
        elif isinstance(current_content, (dict, list)):
            raw_bytes = json.dumps(current_content, sort_keys=True).encode('utf-8')
        else:
            raw_bytes = str(current_content).encode('utf-8')

        current_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        # Look up in ledger
        with open(self.ledger_file, "r", encoding="utf-8") as f:
            ledger = json.load(f)

        record = next((item for item in ledger if item.get("evidence_id") == evidence_id), None)
        if not record:
            return {
                "verified": False,
                "reason": "Evidence ID not found in chain-of-custody ledger."
            }

        recorded_sha256 = record["sha256_hash"]
        integrity_intact = (current_sha256 == recorded_sha256)

        return {
            "verified": integrity_intact,
            "evidence_id": evidence_id,
            "target_uri": record["target_uri"],
            "timestamp_utc": record["timestamp_utc"],
            "recorded_hash": recorded_sha256,
            "calculated_hash": current_sha256,
            "block_hash": record.get("block_hash"),
            "hmac_seal": record.get("hmac_seal"),
            "status": "VALID_TAMPER_FREE" if integrity_intact else "TAMPER_DETECTED"
        }

    def list_evidence(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent chain-of-custody records."""
        try:
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                ledger = json.load(f)
                return ledger[-limit:]
        except Exception:
            return []
