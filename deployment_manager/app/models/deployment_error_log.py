import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

@dataclass
class DeploymentErrorLog:
    error_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str = ""                   # link to the request
    timestamp: datetime = datetime.now(timezone.utc)
    error_type: str = ""                   # e.g. ValidationError, NetworkError
    error_message: str = ""
    stack_trace: str | None = None
