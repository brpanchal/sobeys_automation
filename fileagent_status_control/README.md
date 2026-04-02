# Introduction 
Connect Direct (CD) File Agent Status controlling utility is to enable/disable the file agent status for the configured CD nodes.

Utility is using below APIs.

**GET Int Parm**
The Get Init Parms API is used to retrieve the current file agent status of a node on Connect:Direct server.

**PUT Update Process API**
Update Init Parms API is used to alter the current file agent status of a node on the Connect:Direct server.

┌──────────┬───────────────────────────┬────────────────┬──────────┬───────────────────────┐
│ Method   │ URI (Endpoint)            │ Parameter Name │ Required │ Valid Values          │
├──────────┼───────────────────────────┼────────────────┼──────────┼───────────────────────┤
│ GET      │/cdwebconsole/svc/initparms│ formatOutput   │ Optional │  y or n               │
│ PUT      │/cdwebconsole/svc/initparms│ initParmsData  │ Yes      │ {"initParmsData":""}  │
└──────────┴───────────────────────────┴────────────────┴──────────┴───────────────────────┘

#Verification:
verified this utility with below listed version and it is working as expected.
    a) 6.3.0.11 (unix)
    b) 6.2.0.7_iFix027 (unix)
    c) 6.3.0.4_iFix009 (windows)

# Project Setup and Usage Guide
**Prerequisites**
Before you begin, ensure you have the following installed:
1.  Python 3: Ensure Python 3 is installed on your system. You can verify the installation by running:
    Run `python --version`

**Configuration Setup**
Create and configure the following files:
   1. .env: Include environment variables such as API keys, URLs, etc.
   2. node_list_<ENV>.json: It includes the nodes information like node name,hostname, os_type and fileagent flag details
       eg..  [{
                       "node": "<node_name>",
                       "hostname": "<node>.sobeys.com",
                       "os_type":"windows or unix or AIX",
                       "fileagent.enable": "N"
             }]
       Allowed config of fileagent.enable: "Y" or "y" or "N" or "n" only.
       CD File Agent status naming conventions: y/n for Unix ; Y/N for Windows
3. Run this utility. It will updated the file agent status based on the configuration defined in the node_list.json. When running in "execute" mode, it will first take the backup of the existing configuration and then update the fileagent status (Parameter name: fileagent.enable).
Note: It doesn't update any other parameters.

**Installation Steps:**
1.  Clone the repository
    ```bash
    git clone https://SobeysInc@dev.azure.com/SobeysInc/IntegrationPlatform/_git/CDFileAgentController
    
2. Navigate to the Project Directory
    Open your command prompt or terminal and change to the project directory:
    ```bash
    cd fileagent_status_control

3. Install the required packages and modules
    ```bash
    pip install -r requirements.txt

4. Setup Environment

    A) Manual Step: Create a .env file within the `/fileagent_status_control/` folder. Copy the contents from env_info.txt into it.

    B) The following parameter values are required and must be obtained from the Admin. Once received,
      update them in the .env file accordingly like below(eg..).
    **Important**
       Please ensure:
       The file name is exactly .env
       There are no extra extensions (e.g., .env.txt, .env.example, .env.dev)
       The file is placed in the project root directory
       Incorrect filenames may prevent the application from reading configuration values. 

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

