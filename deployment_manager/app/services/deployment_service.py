import json
import logging
from datetime import datetime, timezone
import pandas as pd
from app.constants import MANDATE_ARTIFACTS, INTERFACE_ARTIFACTS, RULE_STATUS_MAPPING, RULE_STATUS
from app.models.b2bi import B2BI
from app.models.connect_direct import ConnectDirect
from app.models.deployment_error_log import DeploymentErrorLog
from app.models.deployment_request import DeploymentRequest
from app.models.deployment_response import DeploymentResponse
from app.models.interface_deployment_model import InterfaceDeploymentModel, DeploymentStatus
from app.services.b2bi_service import B2BIService
from app.services.cd_service import CDServices
from app.services.deployment_tracker import DeploymentTracker
from app.services.git_connector import GitConnector
from app.services.translation_service import TranslationService

logger = logging.getLogger(__name__)

class DeploymentService:
    def __init__(self):
        self.tracker = DeploymentTracker()
        self.git_connector = GitConnector()
        self.translate_service = None
        self.codelist_dict = {}

    def deploy(self, deployment_json):

        # Convert JSON to DeploymentRequest internally
        request = DeploymentRequest(
            env_name=deployment_json["env_name"],
            mode=deployment_json["mode"],
            requested_by=deployment_json["requested_by"],
            interfaces=deployment_json["interfaces"],
            branch_name=deployment_json["branch_name"],
            repo_name=deployment_json["repo_name"],
        )
        logger.info(f"Deployment request: {request}")

        interface_deployments = []
        start_time = datetime.now(timezone.utc)
        duration = 0
        """Manage full deployment lifecycle."""
        try:
            self.translate_service = TranslationService(deployment_json.get('deploy_config'))
            # validate deployment artifacts
            self.check_deployment_prerequisites(request)

            # 1️⃣ Log initial request
            request.status = "IN_PROGRESS"
            logger.info(f"Deployment Status: {request.status}")
            self.tracker.save_request(request)

            logger.info(f"Starting deployment for {request.env_name} with interfaces {request.interfaces}")

            # 2️⃣ Simulate deployment process (replace with actual logic)
            # Getting only True interface lists
            for interface, cd_rule in request.interfaces:
                    logger.info(f"=============== Deploying interface: {interface} ===============")
                    idm = InterfaceDeploymentModel(interface_name=interface)
                    interface_deployments.append(idm)
                    idm.mark_in_progress()
                    # Generate updated paths
                    updated_artifact = [path.replace('<interface>', interface) for path in INTERFACE_ARTIFACTS]
                    status, failed_msg = self.git_connector.verify_artifacts_exist(updated_artifact, request.repo_name)

                    if not status:
                        error_message = f"Deployment failed for {interface} due to {failed_msg}"
                        logger.error(error_message)
                        idm.mark_failed(error_message)
                        continue

                    try:
                        source_node, host_info = self.check_interface_deployment_prerequisites(request, updated_artifact, deployment_json)
                        if source_node and host_info is False:
                            raise RuntimeError(f"Hostname/Node information not found for {source_node} in host.json")

                        #B2BI Deployment
                        b2bi_obj = self.b2bi_deployment(interface, request, updated_artifact[2])
                        idm.b2bi_artifacts["b2bi_obj"] = b2bi_obj

                        #CD Deployment
                        cd_obj = self.process_cd_artifacts(deployment_json, request, updated_artifact, source_node, cd_rule)
                        if cd_obj.node_name:
                            idm.cd_artifacts["cd_obj"] = cd_obj
                            cd_service = CDServices()
                            cd_service.deploy_cd_artifacts(cd_obj, request.env_name, request.mode)
                        idm.mark_success()

                    except Exception as e:
                        error_message = f"Failed to Deploy artifact for {interface} due to {e}"
                        logger.error(error_message)
                        idm.mark_failed(error_message)
                        logger.warning(f"Skipping deployment for {request.env_name} with interface {interface}")

            #Log success
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            response = DeploymentResponse(
                request_id=request.request_id,
                started_at=start_time,
                completed_at=datetime.now(timezone.utc),
                duration_seconds=duration,
                result_message=f"Deployed {len(request.interfaces)} interfaces successfully",
                status="SUCCESS"
            )
            # logger.info(f"Deployment response: {response}")
            self.tracker.save_response(response)

            # Update final status
            request.status = "SUCCESS"
            logger.info(f"Request status: {request.status}")
            self.tracker.save_request(request)


        except Exception as e:
            # 4️⃣ Log error
            error_log = DeploymentErrorLog(
                request_id=request.request_id,
                error_type=type(e).__name__,
                error_message=str(e)
            )
            logger.warning(f"Deployment error: {error_log}")
            self.tracker.save_error(error_log)

            # Update failed status
            request.status = "FAILED"
            logger.info(f"Request status: {request.status}")
            self.tracker.save_request(request)
            logger.warning(f"Deployment failed: {e}")
        finally:
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            self.print_deployment_summary(interface_deployments, request, duration)
            self.print_deployment_details(interface_deployments, request)
            return request

    def get_cd_artifacts_from_repo(self, request, interface_artifacts, cd_rule, default_cd_rule):
        # Read WatchDirectory.json content
        watch_dir_path = f"{interface_artifacts[0]}/CD/WatchDirectory.json"
        logger.debug(f"WATCH_DIR_PATH: {watch_dir_path}")
        data = self.git_connector.read_json_file(repo_name=request.repo_name, file_path=watch_dir_path)
        watch_dir_json = list(data['watchDirList'].values())[0]
        watch_dir_json = json.dumps(watch_dir_json, indent=4)

        # Read the Rule_list.json content
        rule_list_path = f"{interface_artifacts[0]}/CD/Rule_List.json"
        logger.debug(f"RULE_LIST_PATH: {rule_list_path}")
        rule_list_json = self.git_connector.read_json_file(repo_name=request.repo_name,
                                          file_path=rule_list_path)
        rule_list_json = rule_list_json['rules'][0]

        if cd_rule and pd.notna(cd_rule):
            rule_list_json[RULE_STATUS] = RULE_STATUS_MAPPING.get(cd_rule.strip().lower(), default_cd_rule)
        else:
            rule_list_json[RULE_STATUS] = default_cd_rule

        process_name = rule_list_json.get("procName")
        rule_list_json = json.dumps(rule_list_json, indent=4)

        # Read CDP content
        cdp_path = f"{MANDATE_ARTIFACTS[2]}/{process_name}"
        logger.debug(f"CDP_PATH: {cdp_path}")
        cdp_content = self.git_connector.read_json_file(repo_name=request.repo_name,
                                                        file_path=cdp_path, is_json=False)

        return cdp_content, watch_dir_json, rule_list_json, process_name

    def prepare_cdp_payload(self, cdp_name, cdp_content):
        payload = {
            "processFileName": f"{cdp_name}",
            "processFileData": f"{cdp_content}",
            "overrideProcessFile": ""
        }
        return payload

    def process_cd_artifacts(self, deployment_json, request, interface_artifacts, source_node, cd_rule):
        cd_obj = ConnectDirect()
        cd_obj.node_name = source_node

        if source_node:
            source_node = self.translate_service.translate_artifact(source_node)
            logger.debug(f"Source node: {source_node}")

            # Extract node details from host.json
            for host in deployment_json["hosts"].get('hosts', []):
                if host["nodename"] == source_node:
                    cd_obj.credentials = host["password"]
                    cd_obj.hostname = host["hostname"]
                    cd_obj.node_name = source_node
                    cd_obj.os_type = host["os"]
                    break

            if cd_obj.hostname is None:
                raise RuntimeError(f"Hostname not found for {source_node} in host.json")
            if cd_obj.os_type is None:
                raise RuntimeError(f"OS not found for {source_node} in host.json")
            if cd_obj.credentials is None:
                raise RuntimeError(f"Credential not found for {source_node} in host.json")

            default_cd_rule = deployment_json.get('default_cd_rule')

            cdp_content, watch_dir_json, rule_list_json, cdp_name = self.get_cd_artifacts_from_repo(request, interface_artifacts, cd_rule, default_cd_rule)

            # Replace if any dynamic variables are present in artifacts
            cd_obj.cdp_name = cdp_name
            cdp_content = self.prepare_cdp_payload(cdp_name, cdp_content)
            cdp_dump = json.dumps(cdp_content, indent=4)
            cd_obj.cdp = self.translate_service.translate_artifact(str(cdp_dump))
            cd_obj.watch_dir = self.translate_service.translate_artifact(str(watch_dir_json))
            cd_obj.rule = self.translate_service.translate_artifact(str(rule_list_json))
        else:
            logger.warning(f"Source node not found or null/Empty : {source_node}")
        return cd_obj


    def check_deployment_prerequisites(self, request):
        self.git_connector.update_branch_name(request.branch_name)
        status, failed_msg = self.git_connector.verify_artifacts_exist(MANDATE_ARTIFACTS, request.repo_name)
        if not status:
            raise Exception(f"Deployment prerequisites check failed due to {failed_msg}.")

    def print_deployment_summary(self, deployments, request, total_duration):
        logger.info("\n")
        logger.info("-" * 60)
        logger.info("Deployment Summary:")
        logger.info(f"Environment: {request.env_name}, Total interfaces: {len(deployments)}")
        logger.info("-" * 60)
        # Print header
        logger.info(f"{'Sr.No':<6} | {'Interface Name':<50} | {'Status':<12} | {'Duration':<10} | Message")

        # Iterate through deployments
        for idx, d in enumerate(deployments, start=1):
            duration = (
                (d.end_time - d.start_time).seconds if d.start_time and d.end_time else "N/A"
            )
            logger.info(
                f"{idx:<6} | {d.interface_name:<50} | {d.status.value:<12} | {str(duration) + 's':<10} | {d.message}"
            )
        logger.info("-" * 60)

        success_count = sum(1 for d in deployments if d.status == DeploymentStatus.SUCCESS)
        fail_count = sum(1 for d in deployments if d.status == DeploymentStatus.FAILED)
        if fail_count > 0:
            request.status = DeploymentStatus.FAILED
        else:
            request.status = DeploymentStatus.SUCCESS
        logger.info(f"Success: {success_count}   Failed: {fail_count}")
        logger.info(f"Total deployment duration: {total_duration} seconds")
        logger.info(f"Completed at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

    def format_b2bi_message(self, b2bi_obj):
        fields = {
            "IDENTIFY_CONSUMER" : b2bi_obj.identify_consumer,
            "DELIVERY_CD": b2bi_obj.delivery_cd,
            "DELIVERY_GEN": b2bi_obj.delivery_gen,
            "DELIVERY_SFTP": b2bi_obj.delivery_sftp,
            "DELIVERY_WSMQ": b2bi_obj.delivery_wsmq,
            "DELIVERY_FILESYSTEM": b2bi_obj.delivery_filesystem,
            "DELIVERY_DB": b2bi_obj.delivery_db,
            "DELIVERY_AZURE_FILESTORAGE": b2bi_obj.delivery_azure_filestorage,
            "COLLECT_SFTP": b2bi_obj.collect_sftp,
            "DELIVERY_EMAIL": b2bi_obj.delivery_email,
        }

        # Build message dynamically for non-empty fields
        details = "\n".join([f"{key} : {value}" for key, value in fields.items() if value])
        return f"{details}"

    def print_deployment_details(self, deployments, request):
        logger.info("\n")
        logger.info("-" * 60)
        logger.info("Deployment Details:")
        logger.info(f"Environment: {request.env_name}, Total interfaces: {len(deployments)}")
        logger.info("-" * 60)
        # Print header
        logger.info(f"{'Sr.No':<6} | {'Interface Name':<50} | {'Status':<12} | {'Duration':<10} | Message")

        # Iterate through deployments
        for idx, d in enumerate(deployments, start=1):
            duration = (
                (d.end_time - d.start_time).seconds if d.start_time and d.end_time else "N/A"
            )

            if d.cd_artifacts and d.b2bi_artifacts:
                cd_obj = d.cd_artifacts.get('cd_obj')
                b2bi_obj = d.b2bi_artifacts.get('b2bi_obj')
                logger.info(f"{idx:<6} | {d.interface_name:50} | {d.status.value:12} | Duration: {duration}s |\n"
                        f"CD artifacts: \nWATCH_DIR : {cd_obj.watch_dir}\nRULE : {cd_obj.rule}\nCDP : {cd_obj.cdp}\n"
                        f"\nB2Bi artifacts: \n{self.format_b2bi_message(b2bi_obj)}\nMsg: {d.message}")
            elif d.cd_artifacts:
                cd_obj = d.cd_artifacts.get('cd_obj')
                logger.info(f"{idx:<6} | {d.interface_name:50} | {d.status.value:12} | Duration: {duration}s |\n"
                        f"CD artifacts: \nWATCH_DIR : {cd_obj.watch_dir}\nRULE : {cd_obj.rule}\nCDP : {cd_obj.cdp}\n"
                        f"\nB2Bi artifacts: {d.b2bi_artifacts}\n Msg: {d.message}")
            elif d.b2bi_artifacts:
                b2bi_obj = d.b2bi_artifacts.get('b2bi_obj')
                logger.info(f"{idx:<6} | {d.interface_name:50} | {d.status.value:12} | Duration: {duration}s |\n"
                        f"CD artifacts: {d.cd_artifacts}\n"
                        f"\nB2Bi artifacts: \n{self.format_b2bi_message(b2bi_obj)}\nMsg: {d.message}")
            else:
                logger.info(f"{idx:<6} | {d.interface_name:50} | {d.status.value:12} | Duration: {duration}s |\n"
                        f"CD artifacts: {d.cd_artifacts} | B2Bi artifacts: {d.b2bi_artifacts}  | Msg: {d.message}"
                )
        logger.info("-" * 60)

        success_count = sum(1 for d in deployments if d.status == DeploymentStatus.SUCCESS)
        fail_count = sum(1 for d in deployments if d.status == DeploymentStatus.FAILED)
        if fail_count > 0:
            request.status = DeploymentStatus.FAILED
        else:
            request.status = DeploymentStatus.SUCCESS
        logger.info(f"Success: {success_count}   Failed: {fail_count}")

    def fetch_codelist(self, repo_name, file_path):
        logger.debug(f"Fetching codelist from PATH: {file_path}")
        try:
            codelist_json = json.dumps(
                self.git_connector.read_json_file(repo_name=repo_name,
                                                  file_path=file_path), indent=4)
            codelist_str = self.translate_service.translate_artifact(str(codelist_json))
            return json.loads(codelist_str)
        except Exception as e:
            raise Exception(f"Failed to fetch codelist from {file_path}: {e}")

    def fetch_all_codelist_entry(self, b2bi_artifact, request):
        b2bi_obj = B2BI()
        file_list = self.git_connector.fetch_file_list_from_dir(request.repo_name, b2bi_artifact, request.branch_name)
        for file_path in file_list:
            if 'SBYS_FW_IDENTIFY_CONSUMER' in file_path:
                b2bi_obj.identify_consumer = self.fetch_codelist(request.repo_name, file_path)
            elif 'SBYS_FW_DELIVERY_CD' in file_path:
                b2bi_obj.delivery_cd.append(self.fetch_codelist(request.repo_name, file_path))
            elif 'SBYS_FW_DELIVERY_GEN' in file_path:
                b2bi_obj.delivery_gen.append(self.fetch_codelist(request.repo_name, file_path))
            elif 'SBYS_FW_DELIVERY_SFTP' in file_path:
                b2bi_obj.delivery_sftp.append(self.fetch_codelist(request.repo_name, file_path))
            elif 'SBYS_FW_DELIVERY_WSMQ' in file_path:
                b2bi_obj.delivery_wsmq.append(self.fetch_codelist(request.repo_name, file_path))
            elif 'SBYS_FW_DELIVERY_FILESYSTEM' in file_path:
                b2bi_obj.delivery_filesystem.append(self.fetch_codelist(request.repo_name, file_path))
            elif 'SBYS_FW_DELIVERY_DB' in file_path:
                b2bi_obj.delivery_db.append(self.fetch_codelist(request.repo_name, file_path))
            elif 'SBYS_FW_DELIVERY_AZUREFILESTORAGE' in file_path:
                b2bi_obj.delivery_azure_filestorage.append(self.fetch_codelist(request.repo_name, file_path))
            elif 'SBYS_FW_COLLECT_SFTP' in file_path:
                b2bi_obj.collect_sftp.append(self.fetch_codelist(request.repo_name, file_path))
            elif 'SBYS_FW_EMAIL' in file_path:
                b2bi_obj.delivery_email.append(self.fetch_codelist(request.repo_name, file_path))


        return b2bi_obj

    def b2bi_deployment(self, interface, request, b2bi_artifact):
        b2bi_obj = self.fetch_all_codelist_entry(b2bi_artifact, request)
        b2bi_service = B2BIService(self.codelist_dict)
        b2bi_service.deploy_b2b_artifacts(b2bi_obj, request.env_name, request.mode)
        return b2bi_obj

    def check_interface_deployment_prerequisites(self, request, interface_artifacts, deployment_json):
        # Read interface_metadata.json and get the SourceNode value
        metadata_json = self.git_connector.read_json_file(repo_name=request.repo_name, file_path=interface_artifacts[1])
        source_node = metadata_json.get("SourceNode")

        host_info = False
        if source_node:
            source_node = self.translate_service.translate_artifact(source_node)
            logger.debug(f"Source node: {source_node}")

            # Extract node details from host.json
            for host in deployment_json["hosts"].get('hosts', []):
                if host["nodename"] == source_node:
                    host_info = True
                    break

        return source_node, host_info

