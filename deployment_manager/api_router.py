import logging

import requests
from app.api_gateway import ApiGateway

logger = logging.getLogger(__name__)

class ApiRouter:
    def __init__(self, mode="local", base_url="http://localhost:8000/api"):
        """
        mode = 'local'  → call ApiGateway methods directly
        mode = 'remote' → call REST endpoints (future)
        """
        self.mode = mode
        self.base_url = base_url
        self.gateway = ApiGateway() if mode == "local" else None
        logger.info(f"mode: {self.mode}, base_url: {self.base_url}, gateway: {self.gateway}")

    def load_required_configuration(self):
        if self.mode == "local":
            self.gateway.load_required_configuration()

    def reload_required_configuration(self):
        if self.mode == "local":
            self.gateway.reload_required_configuration()

    def get_all_environments(self):
        if self.mode == "local":
            return self.gateway.get_all_environments()
        else:
            response = requests.post(f"{self.base_url}/environments", json=None)
            return response.json()

    def get_environment(self, name):
        if self.mode == "local":
            return self.gateway.get_environment(name)
        else:
            response = requests.post(f"{self.base_url}/environment", json=None)
            return response.json()

    def deploy(self, payload):
        if self.mode == "local":
            return self.gateway.deploy(payload)
        else:
            response = requests.post(f"{self.base_url}/deploy", json=payload)
            return response.json()

    def get_deployment_status(self, deployment_id):
        if self.mode == "local":
            return self.gateway.get_deployment_status(deployment_id)
        else:
            response = requests.get(f"{self.base_url}/deploy/status/{deployment_id}")
            return response.json()

    def get_deployment_request_by_id(self, deployment_id):
        if self.mode == "local":
            return self.gateway.get_requests_by_id(deployment_id)
        else:
            response = requests.get(f"{self.base_url}/deploy/request/{deployment_id}")
            return response.json()

    def get_deployment_response_by_id(self, deployment_id):
        if self.mode == "local":
            return self.gateway.get_responses_by_id(deployment_id)
        else:
            response = requests.get(f"{self.base_url}/deploy/response/{deployment_id}")
            return response.json()

    def get_deployment_errors_by_id(self, deployment_id):
        if self.mode == "local":
            return self.gateway.get_errors_by_id(deployment_id)
        else:
            response = requests.get(f"{self.base_url}/deploy/errors/{deployment_id}")
            return response.json()
