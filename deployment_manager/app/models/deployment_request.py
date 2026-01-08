import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import uuid

logger = logging.getLogger(__name__)

@dataclass
class DeploymentRequest:
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    env_name: str = ""                     # e.g. "DEV", "PROD"
    mode: str = ""                     # e.g. "DRY_RUN", "ACTUAL_RUN"
    requested_by: str = ""                 # who initiated the deployment
    interfaces: list[str] = field(default_factory=list)  # list of interface names
    requested_at: datetime = datetime.now(timezone.utc)
    status: str = "PENDING"                # PENDING | IN_PROGRESS | SUCCESS | FAILED
    branch_name: str = ""
    repo_name: str = ""

    def to_dict(self):
        """Convert dataclass to dict (convert list to JSON string for CSV)."""
        d = asdict(self)
        d["interfaces"] = json.dumps(self.interfaces)  # store as JSON string in CSV
        d["requested_at"] = self.requested_at.isoformat()
        return d