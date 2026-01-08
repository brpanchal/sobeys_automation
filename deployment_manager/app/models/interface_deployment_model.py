from enum import Enum
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel


class DeploymentStatus(Enum):
    PENDING = "Pending"
    IN_PROGRESS = "In Progress"
    SUCCESS = "Success"
    FAILED = "Failed"


class InterfaceDeploymentModel(BaseModel):
    interface_name: str
    status: DeploymentStatus = DeploymentStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    message: Optional[str] = None
    cd_artifacts: Optional[dict] = dict()
    b2bi_artifacts: Optional[dict] = dict()

    def mark_in_progress(self):
        self.status = DeploymentStatus.IN_PROGRESS
        self.start_time = datetime.now(timezone.utc)

    def mark_success(self, message: str = None):
        self.status = DeploymentStatus.SUCCESS
        self.end_time = datetime.now(timezone.utc)
        self.message = message or "Deployment succeeded."

    def mark_failed(self, message: str = None):
        self.status = DeploymentStatus.FAILED
        self.end_time = datetime.now(timezone.utc)
        self.message = message or "Deployment failed."
