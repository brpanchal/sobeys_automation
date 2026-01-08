# Introduction 
Auto Deployment Manager deploys the configured interfaces to a given environment. 
Deployment includes CD rules, watched directories, CDPs and B2BI codelists.

# Project Setup and Usage Guide
**Prerequisites**
Before you begin, ensure you have the following installed:
1.  Python 3: Ensure Python 3 is installed on your system. You can verify the installation by running:
    Run `python --version`

**Configuration Setup**
Create and configure the following files:
1. env_config.json: Add your environment-specific configuration settings.
2. .env: Include environment variables such as API keys, database URLs, etc.

**Installation Steps:**
1.  Clone the repository
    ```bash
    git clone -b Deployment_manager https://dev.azure.com/SobeysInc/IntegrationPlatform/_git/Sterling-Deployment-Manager
    
2. Navigate to the Project Directory
    Open your command prompt or terminal and change to the project directory:
    ```bash
    cd Sterling-Deployment-Manager

3. Install the required packages and modules
    ```bash
    pip install -r requirements.txt

4. Setup Environment

    A) Manual Step: Create a .env file within the `/Sterling-Deployment-Manager/` folder. Copy the contents from env_info.txt into it.

    C) The following parameter values are required and must be obtained from the Admin. Once received,
      update them in the .env file accordingly like below(eg..).
        
        GIT_ORGANIZATION=SobeysInc
        GIT_PROJECT=IntegrationPlatform
        GIT_PERSONAL_ACCESS_TOKEN=
        GIT_DOMAIN=https://dev.azure.com
        GIT_DEPLOY_CONFIG_REPO=Sterling-Deploy-Config
        GIT_ARTIFACTS_REPO=Sterling-Artifacts

        # Below parameters are across the environment, set for all the environment like DEV, QA, PROD, SIT etc.
        DEV_CDWS_URL="https://dev-cd.example.com"
        DEV_CD_USER="dev_cd_unix_user"
        DEV_CD_PASSWORD="dev_cd_unix_pass"
        DEV_CD_WIN_USER="dev_cd_win_user"
        DEV_CD_WIN_PASSWORD="dev_cd_win_pass"
        DEV_CD_PROTOCOL=protocol

        DEV_B2B_URL="https://dev-b2b.example.com"
        DEV_B2B_USER="dev_b2b_user"
        DEV_B2B_PASSWORD="dev_b2b_pass"

        # Interface Configuration
        # -------- MQ --------
        WSMQ_DEV_HOSTNAME="dev_mq_hostname"
        WSMQ_DEV_PORT="dev_mq_port"
        WSMQ_DEV_CHANNEL="dev_mq_channel"
        WSMQ_DEV_QMANAGER="dev_mq_qmanager"

        WSMQ_QA_HOSTNAME="qa_mq_hostname"
        WSMQ_QA_PORT="qa_mq_port"
        WSMQ_QA_CHANNEL="qa_mq_channel"
        WSMQ_QA_QMANAGER="qa_mq_qmanager"

5.  Run Utility through Command Line or using.
   - Command Line:
     -  Preview Mode:
         ```bash
         python .\run_adm_cli.py --env "dev" --execution-mode "preview"
     -  Execute Mode:    
        ```bash
        python .\run_adm_cli.py --env "dev" --execution-mode "execute"

# Troubleshooting
### Error while fetching repo ID for Sterling-Deploy-Config: 401 Client Error
Check the GIT_PERSONAL_ACCESS_TOKEN. It might have expired. 
