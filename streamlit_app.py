"""Authenticate before opening any connection to the private dashboard."""
import hashlib
import hmac
import json
import secrets
import ssl
import time
from pathlib import Path

import jwt
import psycopg
from psycopg.types.json import Jsonb
import streamlit as st
import streamlit.components.v1 as components

st.set_page_config(page_title="Household dashboard", layout="wide", initial_sidebar_state="collapsed")


remember = components.declare_component("browser_session", path=str(Path(__file__).parent / "session"))


def save_session(token):
    st.session_state.access_token = token
    st.session_state.browser_command = {"id": secrets.token_hex(12), "op": "store" if token else "clear"}
    st.session_state.pop("last_edit", None)


def verified_user(token, key, accounts):
    if not isinstance(token, str) or len(token) > 2048:
        return None
    try:
        claims = jwt.decode(token, key, algorithms=["HS256"], audience="household-dashboard",
                            options={"require": ["exp", "iat", "sub", "aud"]})
    except jwt.InvalidTokenError:
        return None
    return claims["sub"] if claims["sub"] in accounts else None


def connect():
    return psycopg.connect(st.secrets["DATABASE_URL"], sslmode="verify-full",
                           sslrootcert=ssl.get_default_verify_paths().cafile,
                           connect_timeout=10, prepare_threshold=None)


@st.cache_data(max_entries=2, show_spinner=False)
def load_release(digest):
    with connect() as db:
        row = db.execute("SELECT body FROM dashboard_release WHERE id = 1 AND digest = %s", (digest,)).fetchone()
        if row is None:
            st.rerun()
        return json.loads(row[0])


def authenticate():
    try:
        passwords = dict(st.secrets["accounts"])
        if not passwords or not all(isinstance(p, str) and 16 <= len(p.encode()) <= 72 for p in passwords.values()):
            raise ValueError("Incomplete configuration")
    except (KeyError, ValueError, FileNotFoundError):
        st.title("Sign In")
        st.info("Sign-in is temporarily unavailable.")
        st.stop()
    key = hashlib.sha256(b"household-dashboard/session/v2\0" + json.dumps(passwords, sort_keys=True).encode()).digest()
    cmd = st.session_state.get("browser_command", {"op": "read", "id": "initial"})
    token = st.session_state.get("access_token")
    reply = remember(command=cmd, token=token if cmd["op"] == "store" else None, key="session", default=None)
    if cmd["op"] == "read" and isinstance(reply, dict) and reply.get("id") == cmd["id"]:
        token = reply.get("token")
    viewer = verified_user(token, key, passwords)
    if viewer:
        st.session_state.access_token = token
        return viewer, key, tuple(passwords)
    with st.form("access", clear_on_submit=True):
        st.subheader("Household Sign-In")
        username = st.text_input("Username", autocomplete="username").strip().lower()
        password = st.text_input("Password", type="password", autocomplete="current-password")
        submitted = st.form_submit_button("Sign In")
    if submitted:
        matches = hmac.compare_digest(hashlib.sha256(password.encode()).digest(),
                                      hashlib.sha256(passwords.get(username, "").encode()).digest())
        if matches and username in passwords:
            now = int(time.time())
            save_session(jwt.encode({"sub": username, "aud": "household-dashboard", "iat": now,
                                     "exp": now + 30 * 86400}, key, algorithm="HS256"))
            st.rerun()
        time.sleep(0.4)
        st.error("Check your username and password and try again.")
    st.stop()


viewer, signing_key, accounts = authenticate()
st.markdown("""<style>[data-testid="stMainBlockContainer"]{max-width:1200px;padding:.3rem .5rem 0}
    @media print{[data-testid="stHeader"]{display:none}}</style>""", unsafe_allow_html=True)
view = components.declare_component("private_dashboard", path=str(Path(__file__).parent / "bridge"))


@st.fragment(run_every=12)
def dashboard():
    if verified_user(st.session_state.get("access_token"), signing_key, accounts) != viewer:
        st.rerun()
    try:
        with connect() as db:
            revision, state, digest = db.execute(
                """SELECT household.revision, household.state, release.digest
                   FROM dashboard_read(%s) AS household CROSS JOIN dashboard_release AS release
                   WHERE release.id = 1""", (viewer,)).fetchone()
        release = load_release(digest)
        last = st.session_state.get("last_edit", {})
        edit = view(assets=release["assets"], data=release["data"], state=state, version=revision,
                    ack=last.get("id"), conflict=last.get("conflict", False), key=f"dashboard_{digest}", default=None)
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
st.button("Sign Out", on_click=save_session, args=(None,))
