import logging
from typing import Dict

logger = logging.getLogger(__name__)

class Environment:
    """Represents one environment with environment details, deployment configuration, hosts, and interfaces."""
    def __init__(self, name: str, environment_details:Dict, deployment_config: Dict, hosts: Dict,
                 interfaces: Dict, env_errors):
        self.name = name
        self.environment_details = environment_details
        self.deployment_config = deployment_config  # dict
        self.hosts = hosts            # dict
        self.interfaces = interfaces  # dict
        self.env_errors = env_errors

    def __repr__(self):
        return (
            f"Environment(name={self.name}, "
            f"environment_details={self.environment_details}, "
            f"deployment_config={self.deployment_config}, "
            f"hosts={self.hosts}, "
            f"interfaces={self.interfaces}), "
            f"env_errors={self.env_errors})"
        )
