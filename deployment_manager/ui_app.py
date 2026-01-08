import logging
import logging.config
import streamlit as st
import os
from dotenv import load_dotenv
from app.logger import setup_logging
setup_logging()

from api_router import ApiRouter

logger = logging.getLogger(__name__)

api_router = ApiRouter()
api_router.load_required_configuration()

# =========================
# HEADER SECTION
# =========================
def show_header():
    st.title("Auto Deployment Manager")

def show_environments():
    default_env = "Select Environment"
    environments = ApiRouter().get_all_environments()
    logger.info(f"environments: {environments}")
    env_names = [default_env] + list(environments.keys())

    col1, col2 = st.columns(2)

    with col1:
        selected_env = st.selectbox(
            "Select Deployment Environment", options=env_names, index=env_names.index(default_env)
        )
        if st.button("", help="Click to reload environment configuration", icon="🔄"):
            logger.info(f"Reloading environment configuration for environment {selected_env}")
            api_router.reload_required_configuration()
            st.rerun()

    # Deployment mode radio
    with col2:
        deployment_mode = st.radio("Select Deployment Mode", options=["Dry run", "Actual run"])

    with st.expander("Show Environment Details", expanded=False):
        st.write(api_router.get_all_environments())

    return selected_env, deployment_mode

# =========================
# ✅ DEPLOYMENT CONFIRMATION MODAL
# =========================
@st.dialog("Confirm Deployment")
def confirm_deployment():
    st.write("Are you sure you want to deploy these interfaces?")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("✅ Yes, Deploy"):
            st.session_state.deployed = True
            st.rerun()
    with col2:
        if st.button("❌ Don't Deploy"):
            st.session_state.show_modal = False
            st.rerun()

def handle_deployment(selected_env, deployment_mode):
    if selected_env == "Select Environment":
        return

    selected_environment = ApiRouter().get_environment(selected_env)
    if not selected_environment:
        st.warning("No matching directory found.")
        return

    if selected_environment.env_errors:
        st.error(str(selected_environment.env_errors))
        return

    # Show interfaces
    st.write("Interfaces to be deployed:")
    toggled_values = {}
    for key, value in selected_environment.interfaces.items():
        toggled_values[key] = st.checkbox(key, value=bool(value), disabled=True)

    # Deploy button
    if st.button("🚀 Deploy"):
        st.write(f"Deployment initiated for `{selected_env}` in `{deployment_mode}` mode.")
        checked_interfaces = [key for key, checked in toggled_values.items() if checked]
        st.write("Checked Interfaces:", checked_interfaces)
        st.session_state.checked_interfaces = checked_interfaces
        st.session_state.branch_name = selected_environment.environment_details.get("branch_name")
        confirm_deployment()

def finalize_deployment(selected_env, deployment_mode):
    load_dotenv()
    if st.session_state.get("deployed") and st.session_state.get("checked_interfaces"):
        payload = {
            "env_name": selected_env,
            "mode": deployment_mode,
            "requested_by": "admin",
            "interfaces": st.session_state.get("checked_interfaces"),
            "branch_name":st.session_state.get("branch_name"),
            "repo_name":os.getenv("GIT_ARTIFACTS_REPO")
        }
        # Pass JSON to engine and get deployment ID
        request = ApiRouter().deploy(payload)
        if request:
            deployment_id = request.request_id
        else:
            deployment_id = "Not available"
        st.session_state.deployment_id = deployment_id

        # Reset session state and show success
        st.session_state.deployed = False

        col1, col2 = st.columns(2)
        with col1:
            st.success("Deployment started successfully with id :")
        with col2:
            st.code(deployment_id)

def check_deployment_status():
    with st.expander("Check Deployment Status by ID", expanded=True):
        deployment_id = st.text_input("Enter Deployment ID")

        if st.button("🔍 Check Status") and deployment_id:
            # Fetch requests, responses, errors
            requests = api_router.get_deployment_request_by_id(deployment_id)
            responses = api_router.get_deployment_response_by_id(deployment_id)
            errors = api_router.get_deployment_errors_by_id(deployment_id)
            if requests.empty:
                st.warning(f"No deployment request found for ID: {deployment_id}")
            else:
                st.subheader("Deployment Request(s)")
                st.dataframe(requests)

                st.subheader("Deployment Response(s)")
                if responses.empty:
                    st.info(f"No deployment response found for ID: {deployment_id}")
                else:
                    st.dataframe(responses)

                st.subheader("Deployment Error(s)")
                if errors.empty:
                    st.info("No errors reported")
                else:
                    st.dataframe(errors)

# =========================
# 🌟 MAIN APP
# =========================
def main():
    st.set_page_config(page_title="Auto Deployment Manager", layout="wide")

    # Show sections
    show_header()
    selected_env, deployment_mode = show_environments()
    handle_deployment(selected_env, deployment_mode)
    finalize_deployment(selected_env, deployment_mode)
    check_deployment_status()

if __name__ == "__main__":
    main()