"""Authenticate before opening any connection to the private dashboard."""
import hashlib
import json
import ssl
from pathlib import Path

import bcrypt
import psycopg
from psycopg.types.json import Jsonb
import streamlit as st
import streamlit.components.v1 as components
import streamlit_authenticator as stauth

st.set_page_config(page_title="Household dashboard", layout="wide", initial_sidebar_state="collapsed")


@st.cache_data(show_spinner=False)
def login_config(passwords):
    users = {name: {"name": name, "password": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()}
             for name, password in passwords.items()}
    key = hashlib.sha256(b"household-dashboard/session/v1\0" + json.dumps(passwords, sort_keys=True).encode()).hexdigest()
    return users, key


def connect():
    return psycopg.connect(st.secrets["DATABASE_URL"], sslmode="verify-full",
                           sslrootcert=ssl.get_default_verify_paths().cafile,
                           connect_timeout=10, prepare_threshold=None)


@st.cache_data(ttl=300, show_spinner=False)
def load_release():
    with connect() as db:
        return json.loads(db.execute("SELECT body FROM dashboard_release WHERE id = 1").fetchone()[0])


def authenticate():
    try:
        passwords = dict(st.secrets["accounts"])
        if not passwords or not all(isinstance(p, str) and 16 <= len(p.encode()) <= 72 for p in passwords.values()):
            raise ValueError("Incomplete configuration")
        users, signing_key = login_config(passwords)
    except (KeyError, ValueError, FileNotFoundError):
        st.title("Sign in")
        st.info("Sign-in is temporarily unavailable.")
        st.stop()
    auth = stauth.Authenticate({"usernames": users}, "household_session", signing_key,
                               cookie_expiry_days=30, auto_hash=False)
    auth.login(fields={"Form name": "Household sign-in", "Login": "Sign in"}, clear_on_submit=True)
    viewer = st.session_state.get("username")
    if st.session_state.get("authentication_status") is not True or viewer not in users:
        if st.session_state.get("authentication_status") is False:
            st.error("Check your username and password and try again.")
        st.stop()
    return viewer, auth


viewer, auth = authenticate()
st.markdown("""<style>[data-testid="stMainBlockContainer"]{max-width:1200px;padding:.3rem .5rem 0}
    @media print{[data-testid="stHeader"]{display:none}}</style>""", unsafe_allow_html=True)
view = components.declare_component("private_dashboard", path=str(Path(__file__).parent / "bridge"))


@st.fragment(run_every=12)
def dashboard():
    if st.session_state.get("authentication_status") is not True or st.session_state.get("username") != viewer:
        st.stop()
    try:
        release = load_release()
        with connect() as db:
            revision, state = db.execute("SELECT * FROM dashboard_read(%s)", (viewer,)).fetchone()
        last = st.session_state.get("last_edit", {})
        edit = view(assets=release["assets"], data=release["data"], state=state, version=revision,
                    ack=last.get("id"), conflict=last.get("conflict", False), key="dashboard", default=None)
        if edit and edit.get("id") != last.get("id"):
            with connect() as db:
                result = db.execute("SELECT dashboard_save(%s, %s, %s, %s)",
                                    (viewer, edit["version"], edit["id"], Jsonb(edit["state"]))).fetchone()[0]
            st.session_state.last_edit = {"id": edit["id"], "conflict": result == "conflict"}
            st.rerun()
    except psycopg.DataError:
        st.error("This edit could not be saved. Reload to see the saved version.")
    except (psycopg.Error, IndexError, KeyError, TypeError):
        st.warning("Connecting to your dashboard. This page will retry automatically.")


dashboard()
auth.logout("Sign out")
