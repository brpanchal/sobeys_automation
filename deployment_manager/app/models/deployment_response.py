import logging
from dataclasses import field, dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

@dataclass
class DeploymentResponse:
    request_id: str = ""                   # link back to DeploymentRequest
    started_at: datetime = datetime.now(timezone.utc)
    completed_at: datetime | None = None
    duration_seconds: float = 0.0
    result_message: str = ""               # success message or details
    error_message: str | None = None
    status: str = "SUCCESS"                # SUCCESS | FAILED
