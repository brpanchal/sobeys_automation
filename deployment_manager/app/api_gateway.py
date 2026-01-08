import logging
from app import constants
from app.config_loader import AppConfig
from app.services.deployment_tracker import DeploymentTracker
from app.services.environment_config_service import EnvironmentConfigService
from app.services.deployment_service import DeploymentService

logger = logging.getLogger(__name__)

class ApiGateway:
    """Acts as the backend API gateway, now callable directly,
    later exposable via Flask/FastAPI with the same method signatures."""

    def __init__(self):
        self.deployment_service = DeploymentService()
        self.environment_config_service = None

    # =========================
    # System startup - All of these should be done as part of deployment engine startup
    # =========================
    def load_required_configuration(self) -> EnvironmentConfigService:
        logger.debug(f"/load_required_configuration")
        config = AppConfig(constants.CONFIG_FILENAME)
        self.environment_config_service = EnvironmentConfigService(config.get(constants.ENV_CONFIG_PATH))
        return self.environment_config_service

    def reload_required_configuration(self):
        logger.debug("/reload_required_configuration")
        config = AppConfig(constants.CONFIG_FILENAME)
        self.environment_config_service = EnvironmentConfigService(config.get(constants.ENV_CONFIG_PATH))
        self.environment_config_service.reload(config.get(constants.ENV_CONFIG_PATH))

    def get_default_cdrule_config(self):
        logger.debug("Loading default cd rule config")
        config = AppConfig(constants.CONFIG_FILENAME)
        return config.get(constants.DEFAULT_CD_RULE)

    def get_all_environments(self):
        logger.debug("/get_all_environments")
        config = AppConfig(constants.CONFIG_FILENAME)
        environments = EnvironmentConfigService(config.get(constants.ENV_CONFIG_PATH)).get_all_environments()
        return environments

    def get_environment(self, name):
        logger.debug("/get_environment")
        config = AppConfig(constants.CONFIG_FILENAME)
        environment = EnvironmentConfigService(config.get(constants.ENV_CONFIG_PATH)).get_environment(env_name=name)
        return environment

    def deploy(self, payload):
        logger.debug(f"/deploy")
        return DeploymentService().deploy(payload)

    def get_deployment_status(self, deployment_id):
        logger.debug(f"/get_deployment_status : deployment_id: {deployment_id}")
        pass
        # return self.deployment_service.get_status(deployment_id)

    def get_requests_by_id(self, deployment_id: str):
        logger.debug(f"/get_requests_by_id : deployment_id: {deployment_id}")
        return DeploymentTracker().get_requests_by_id(deployment_id)

    def get_responses_by_id(self, deployment_id: str):
        logger.debug(f"/get_responses_by_id : deployment_id: {deployment_id}")
        return DeploymentTracker().get_responses_by_id(deployment_id)

    def get_errors_by_id(self, deployment_id: str):
        logger.debug(f"/get_errors_by_id : deployment_id: {deployment_id}")
        return DeploymentTracker().get_errors_by_id(deployment_id)
