# Introduction 
Enable disable initparms utils is to update the initparms file agent for particular node to a given environment.

# Project Setup and Usage Guide
**Prerequisites**
Before you begin, ensure you have the following installed:
1.  Python 3: Ensure Python 3 is installed on your system. You can verify the installation by running:
    Run `python --version`

**Configuration Setup**
Create and configure the following files:
1.env: Include environment variables such as API keys, database URLs, etc.
2.node_list.json: It includes the node information like hostname, os_type and initparms details
    eg..  {
            "node": "<node_name>",
            "hostname": "<node>.sobeys.com",
            "os_type":"windows or unix or AIX",
            "fileagent.enable": "N"
          }

**Installation Steps:**
1.  Clone the repository
    ```bash
    git clone <url>
    
2. Navigate to the Project Directory
    Open your command prompt or terminal and change to the project directory:
    ```bash
    cd enable_disable_initparms_utils

3. Install the required packages and modules
    ```bash
    pip install -r requirements.txt

4. Setup Environment

    A) Manual Step: Create a .env file within the `/enable_disable_initparms_utils/` folder. Copy the contents from env_info.txt into it.

    C) The following parameter values are required and must be obtained from the Admin. Once received,
      update them in the .env file accordingly like below(eg..).

        NODE_LIST_FILE="node_list.json"

        # Below parameters are across the environment, set for all the environment like DEV, QA, PROD, SIT etc.
        DEV_CDWS_URL="https://dev-cd.example.com"
        DEV_CD_USER="dev_cd_unix_user"
        DEV_CD_PASSWORD="dev_cd_unix_pass"
        DEV_CD_WIN_USER="dev_cd_win_user"
        DEV_CD_WIN_PASSWORD="dev_cd_win_pass"
        DEV_CD_PROTOCOL=protocol

5.  Run Utility through Command Line or using.
   - Command Line:ss
     -  Preview Mode:
        ```bash
        python run_app.py --env "dev" --execution-mode "preview"
     -  Execute Mode:    
        ```bash
        python run_app.py --env "dev" --execution-mode "execute"

# Troubleshooting


TODO: add details about PUT API 
https://www.ibm.com/docs/en/connect-direct/6.4.0?topic=ipra-put-update-process-api
