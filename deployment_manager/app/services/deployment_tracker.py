import json
import logging

import pandas as pd
import os

from app import constants
from app.config_loader import AppConfig
from app.models.deployment_error_log import DeploymentErrorLog
from app.models.deployment_request import DeploymentRequest
from app.models.deployment_response import DeploymentResponse

logger = logging.getLogger(__name__)

class DeploymentTracker:
    def __init__(self):
        self.base_dir = AppConfig().get(constants.DEPLOYMENT_HISTORY_DATA_DIR)
        #TODO: Check path existence
        os.makedirs(self.base_dir, exist_ok=True)
        self.requests_file = os.path.join(self.base_dir, constants.DEPLOYMENT_REQUESTS_FILE)
        self.responses_file = os.path.join(self.base_dir, constants.DEPLOYMENT_RESPONSES_FILE)
        self.errors_file = os.path.join(self.base_dir, constants.DEPLOYMENT_ERRORS_FILE)

    def save_request(self, req: DeploymentRequest):
        df = pd.DataFrame([req.to_dict()])
        df.to_csv(self.requests_file, mode="a", index=False, header=not os.path.exists(self.requests_file))

    def save_response(self, res: DeploymentResponse):
        df = pd.DataFrame([res.__dict__])
        df.to_csv(self.responses_file, mode="a", index=False, header=not os.path.exists(self.responses_file))

    def save_error(self, err: DeploymentErrorLog):
        df = pd.DataFrame([err.__dict__])
        df.to_csv(self.errors_file, mode="a", index=False, header=not os.path.exists(self.errors_file))

    def get_all_requests(self):
        if not os.path.exists(self.requests_file):
            return pd.DataFrame()
        df = pd.read_csv(self.requests_file)
        # Convert JSON string back to list
        df["interfaces"] = df["interfaces"].apply(lambda x: json.loads(x) if pd.notna(x) else [])
        return df

    def get_all_responses(self):
        return pd.read_csv(self.responses_file) if os.path.exists(self.responses_file) else pd.DataFrame()

    def get_all_errors(self):
        return pd.read_csv(self.errors_file) if os.path.exists(self.errors_file) else pd.DataFrame()

    def get_requests_by_id(self, deployment_id: str):
        df = self.get_all_requests()  # Load all requests
        if df.empty:
            return pd.DataFrame()  # Return empty DataFrame if no requests
        # Filter by deployment_id
        result = df[df["request_id"] == deployment_id]
        return result  # Can be empty DataFrame if no matches

    def get_responses_by_id(self, deployment_id: str):
        df = self.get_all_responses()  # Load all requests
        if df.empty:
            return pd.DataFrame()  # Return empty DataFrame if no requests
        # Filter by deployment_id
        result = df[df["request_id"] == deployment_id]
        return result  # Can be empty DataFrame if no matches

    def get_errors_by_id(self, deployment_id: str):
        df = self.get_all_errors()  # Load all requests
        if df.empty:
            return pd.DataFrame()  # Return empty DataFrame if no requests
        # Filter by deployment_id
        result = df[df["request_id"] == deployment_id]
        return result  # Can be empty DataFrame if no matches