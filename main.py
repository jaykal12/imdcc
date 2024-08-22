import streamlit as st
import hashlib
import os
import socket
from tinydb import TinyDB, Query
from datetime import datetime

# Initialize databases
db = TinyDB('db.json')
failed_attempts = TinyDB('failed_attempts.json')

# Ensure 'uploaded_files' directory exists
if not os.path.exists('uploaded_files'):
    os.makedirs('uploaded_files')

# Set correct username and hashed password
USERNAME = "malik"
PASSWORD_HASH = hashlib.sha256("oteiut_yust*212".encode()).hexdigest()

# Block IP after 6 failed attempts
def is_ip_blocked(ip):
    record = failed_attempts.get(Query().ip == ip)
    if record and record['attempts'] >= 6:
        return True
    return False

def register_failed_attempt(ip):
    record = failed_attempts.get(Query().ip == ip)
    if record:
        failed_attempts.update({'attempts': record['attempts'] + 1}, Query().ip == ip)
    else:
        failed_attempts.insert({'ip': ip, 'attempts': 1, 'timestamp': datetime.now().isoformat()})

def reset_attempts(ip):
    failed_attempts.remove(Query().ip == ip)

# Get user IP address
def get_ip():
    return socket.gethostbyname(socket.gethostname())

# Login Page
def login():
    ip = get_ip()

    if is_ip_blocked(ip):
        st.error("Your IP has been blocked due to multiple failed login attempts.")
        return False

    st.title("Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username == USERNAME and hashlib.sha256(password.encode()).hexdigest() == PASSWORD_HASH:
            reset_attempts(ip)
            return True
        else:
            st.error("Invalid username or password.")
            register_failed_attempt(ip)
    return False

# File Uploading
def file_manager():
    st.title("Document Manager")

    uploaded_file = st.file_uploader("Upload a file", type=['pdf', 'jpg', 'jpeg', 'mp4', 'txt'])
    if uploaded_file:
        file_path = os.path.join("uploaded_files", uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        st.success(f"File {uploaded_file.name} saved successfully!")

    files = os.listdir("uploaded_files")
    if files:
        st.subheader("Available Files:")
        for file in files:
            file_path = os.path.join("uploaded_files", file)
            st.download_button(f"Download {file}", data=open(file_path, "rb"), file_name=file)
            if st.button(f"Delete {file}", key=f"delete_{file}"):
                os.remove(file_path)
                st.warning(f"{file} deleted.")

# Notepad
def notepad():
    st.title("Notepad")

    note = st.text_area("Write your notes here...", height=200)
    if st.button("Save Note"):
        with open("notes.txt", "w") as f:
            f.write(note)
        st.success("Note saved!")

    if os.path.exists("notes.txt"):
        with open("notes.txt", "r") as f:
            saved_note = f.read()
        st.text_area("Saved Notes", saved_note, height=200)

# Main App
def main():
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox("Choose a page", ["Home", "Upload Files", "Notepad"])

    if page == "Home":
        st.write("Welcome to the Document Management and Notepad App")
    elif page == "Upload Files":
        file_manager()
    elif page == "Notepad":
        notepad()

if __name__ == '__main__':
    if login():
        main()
