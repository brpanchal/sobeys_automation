# Introduction 
Initparms access control utility is to enable/disable the initparms file agent for particular node to a given environment.

**GET Int Parm**
The Get Init Parms API is used to retrieve the current initialization parameters of the Connect:Direct server.

**PUT Update Process API**
Update Init Parms API is used to alter the initialization parameters of the Connect:Direct server.

┌──────────┬───────────────────────────┬────────────────┬──────────┬───────────────────────┐
│ Method   │ URI (Endpoint)            │ Parameter Name │ Required │ Valid Values          │
├──────────┼───────────────────────────┼────────────────┼──────────┼───────────────────────┤
│ GET      │/cdwebconsole/svc/initparms│ formatOutput   │ Optional │  y or n               │
│ PUT      │/cdwebconsole/svc/initparms│ initParmsData  │ Yes      │ {"initParmsData":""}  │
└──────────┴───────────────────────────┴────────────────┴──────────┴───────────────────────┘

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
    1) fileagent.enable: "Y" or "y" or "N" or "n" 							------- allowed -- will be skipping or update accordingly
    2) fileagent.enable: any other value apart "Y" or "y" or "N" or "n" 	-------not allowed -- will be skipping
    #Skip/Skipped: Status of node which skip due to same status or requested fileagent status have invalid or not configured.
    #Update/updated: Status of node which update the fileagent with enable/disable(Y/N) flag.

**Installation Steps:**
1.  Clone the repository
    ```bash
    git clone <url>
    
2. Navigate to the Project Directory
    Open your command prompt or terminal and change to the project directory:
    ```bash
    cd initparms_access_control

3. Install the required packages and modules
    ```bash
    pip install -r requirements.txt

4. Setup Environment

    A) Manual Step: Create a .env file within the `/initparms_access_control/` folder. Copy the contents from env_info.txt into it.

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

