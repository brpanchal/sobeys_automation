import logging
import os
import pandas as pd
from io import StringIO
import requests
from dotenv import load_dotenv

from app.constants import BRANCH_PARAMS_SINGLE, BRANCH_PARAMS_RECURSIVE

logger = logging.getLogger(__name__)
load_dotenv()

class GitConnector:
    def __init__(self):
        self.git_organization = os.getenv("GIT_ORGANIZATION")
        self.git_project = os.getenv("GIT_PROJECT")
        self.pat = os.getenv("GIT_PERSONAL_ACCESS_TOKEN")
        self.git_domain = os.getenv("GIT_DOMAIN")
        self.params = BRANCH_PARAMS_SINGLE

    def update_branch_name(self, branch_name):
        self.params['versionDescriptor.version'] = branch_name
        logger.debug("Set branch name: %s", branch_name)

    def create_repo_url(self, repo_name, action_type, file_path=None):
        base = f"{self.git_domain}/{self.git_organization}/{self.git_project}/_apis/git/repositories/{repo_name}"
        if action_type == "basepath":
            return f"{base}?api-version=7.0"
        if action_type == "fetchSingleFile":
            return f"{base}/items?path={file_path}&api-version=7.0"
        if action_type == "fetchAllFiles":
            return f"{base}/items"
        return ""

    def fetch_repo_id_with_repo_name(self, repo_name):
        logger.debug("Fetching repo id for repo: %s", repo_name)
        try:
            response = requests.get(self.create_repo_url(repo_name, "basepath"), auth=('', self.pat))
            response.raise_for_status()
            return response.json().get('id')
        except requests.RequestException as e:
            logger.error(f"Error while fetching fetching repo ID for {repo_name}: %s", e)
            return None

    def verify_artifacts_exist(self, target_paths, repo_name):
        logger.debug(f"target_paths: {target_paths}, repo_name: {repo_name}")
        repo_id = self.fetch_repo_id_with_repo_name(repo_name)
        if not repo_id:
            return False, "Repository ID not found"

        repo_url = self.create_repo_url(repo_id, "fetchAllFiles")
        base_params = {k: v for k, v in self.params.items() if k not in {'recursionLevel', 'scopePath'}}

        for path in target_paths:
            try:
                response = requests.get(repo_url, auth=('', self.pat), params={**base_params, 'path': path})
                response.raise_for_status()
                logger.debug("Found: %s (%s)", path, response.json().get('gitObjectType'))

            except requests.HTTPError as e:
                msg = f"Directory not found: {path}"
                logger.error(msg)
                return False, msg
            except requests.RequestException as e:
                logger.error("Request failed: %s", e)
                return False, str(e)

        return True, None

    def read_json_file(self, repo_name, file_path, is_json=True):
        logger.debug("Reading file: %s from repo: %s", file_path, repo_name)
        repo_url = self.create_repo_url(repo_name, "fetchSingleFile", file_path)
        params = {k: v for k, v in self.params.items() if k not in {'recursionLevel', 'scopePath'}}

        try:
            response = requests.get(repo_url, auth=('', self.pat), params=params)
            response.raise_for_status()
            if not is_json:
                content = response.text
            else:
                content = response.json()
            # logger.debug("File content: %s", content)
            return content
        except requests.RequestException as e:
            logger.error("Failed to read file: %s", e)
            raise Exception(f"Failed to read file: {e}")

    def read_csv_file(self, repo_name, file_path):
        logger.debug("Reading CSV file: %s from repo: %s", file_path, repo_name)
        repo_url = self.create_repo_url(repo_name, "fetchSingleFile", file_path)
        params = {k: v for k, v in self.params.items() if k not in {'recursionLevel', 'scopePath'}}

        try:
            response = requests.get(repo_url, auth=('', self.pat), params=params)
            response.raise_for_status()
            df = pd.read_csv(StringIO(response.text))
            data_dict = df.to_dict(orient='records')

            # logger.debug("File content: %s", data_dict)
            return data_dict
        except requests.RequestException as e:
            logger.error("Failed to read csv file: %s", e)
            raise Exception(f"Failed to read csv file: {e}")


    def fetch_file_list_from_dir(self, repo_name, directory_path=None, branch_name=None):
        logger.debug("Fetching file list from repo: %s", repo_name)
        if directory_path is not None:
            params = BRANCH_PARAMS_RECURSIVE
            params['scopePath'] = directory_path
            params['versionDescriptor.version'] = branch_name
        else:
            params = self.params
        repo_id = self.fetch_repo_id_with_repo_name(repo_name)
        if not repo_id:
            return []

        repo_url = self.create_repo_url(repo_id, "fetchAllFiles")
        try:
            response = requests.get(repo_url, auth=('', self.pat), params=params)
            response.raise_for_status()
            items = response.json().get('value', [])
        except requests.RequestException as e:
            logger.error("Failed to fetch files: %s", e)
            return []

        if directory_path is not None:
            return sorted([item['path'] for item in items if item['gitObjectType'] != 'tree'])

        else:
            return sorted([
            item['path'].split('/')[-1]
            for item in items
            if item.get('gitObjectType') == 'blob' and item['path'].split('/')[-1] != 'README.md'
            ])