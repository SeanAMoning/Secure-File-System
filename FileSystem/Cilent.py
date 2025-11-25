
# =============================
# Client 
# =============================

import socket
import json
import getpass
import os
import hmac
import hashlib
import base64
import time

SECRET_KEY = b'super_secret_key_for_hmac'
SESSION_FILE = 'sessions.json'

class Token:
    def __init__(self, username, groups, timestamp=None):
        self.username = username
        self.groups = groups
        self.timestamp = timestamp

    def to_dict(self):
        token_data = {"username": self.username, "groups": self.groups}
        if self.timestamp is not None:
            token_data["timestamp"] = self.timestamp
        return token_data

    @staticmethod
    def from_dict(data):
        return Token(data["username"], data["groups"], data.get("timestamp"))

def verify_token(token_dict, signature):
    msg = json.dumps(token_dict, sort_keys=True).encode()
    expected_sig = hmac.new(SECRET_KEY, msg, hashlib.sha256).digest()
    return hmac.compare_digest(base64.b64encode(expected_sig).decode(), signature)

def connect(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        return s
    except:
        print("[Client] Connection failed.")
        return None

def send_request(sock, request):
    sock.sendall(json.dumps(request).encode())
    response = sock.recv(4096)
    return json.loads(response.decode())

def save_session(username, token_data, signature):
    sessions = {}
    expiry_time = time.time() + 600  # Token valid for 10 minutes
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE, 'r') as f:
            sessions = json.load(f)
    sessions[username] = {
        'token': token_data,
        'signature': signature,
        'timestamp': time.time(),
        'expires_at': expiry_time
    }
    with open(SESSION_FILE, 'w') as f:
        json.dump(sessions, f, indent=2)
    # Log token sharing for documentation
    with open("token_log.txt", "a") as log:
        log.write(f"[{time.ctime()}] Token issued to '{username}':")
        log.write(json.dumps(token_data, indent=2))
        log.write(f"Signature: {signature}")
        log.write(f"Expires at: {time.ctime(expiry_time)}")
        log.write("=" * 50 + "")


def load_session(username):
    if not os.path.exists(SESSION_FILE):
        return None
    with open(SESSION_FILE, 'r') as f:
        sessions = json.load(f)
    session = sessions.get(username)
    if session and time.time() - session["timestamp"] <= 600:
        token = Token.from_dict(session["token"])
        return token, session["signature"]
    return None

def upload_file(file_sock, current_token, current_signature):
    filepath = input("Enter path to the file to upload: ").strip()
    if not os.path.isfile(filepath):
        print("[ERROR] File not found.")
        return

    group = input("Enter group to associate this file with: ").strip()
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)

    request = {
        "command": "upload",
        "token": current_token.to_dict(),
        "signature": current_signature,
        "filename": filename,
        "filesize": filesize,
        "group": group
    }
    file_sock.sendall(json.dumps(request).encode())

    response = file_sock.recv(4096)
    try:
        response = json.loads(response.decode())
    except Exception as e:
        print(f"[ERROR] Failed to parse server response: {e}")
        return

    if not response.get("status"):
        print("[ERROR] Upload request was denied:", response.get("reason"))
        return

    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            file_sock.sendall(chunk)

    print(f"[UPLOAD COMPLETE] '{filename}' uploaded to group '{group}'.")

def download_file(file_sock, current_token, current_signature):
    filename = input("Enter filename to download: ").strip()

    request = {
        "command": "download",
        "token": current_token.to_dict(),
        "signature": current_signature,
        "filename": filename
    }
    file_sock.sendall(json.dumps(request).encode())

    response = file_sock.recv(4096)
    try:
        response = json.loads(response.decode())
    except Exception as e:
        print(f"[ERROR] Failed to parse server response: {e}")
        return

    if not response.get("status"):
        print("[ERROR] Download request was denied:", response.get("reason"))
        return

    filesize = response.get("filesize")
    file_sock.sendall(b'READY')

    save_path = os.path.join("downloads", filename)
    os.makedirs("downloads", exist_ok=True)

    with open(save_path, 'wb') as f:
        received = 0
        while received < filesize:
            chunk = file_sock.recv(min(65536, filesize - received))
            if not chunk:
                break
            f.write(chunk)
            received += len(chunk)

    print(f"[DOWNLOAD COMPLETE] '{filename}' saved to 'downloads/' folder.")

def client_menu(group_sock=None, file_sock=None, current_token=None, current_signature=None):
    mode = "group" if group_sock else "file"

    if mode == "file":
        file_sock.sendall(b"HELLO")
        try:
            ack = file_sock.recv(1024)
        except Exception as e:
            print(f"[ERROR] Failed during handshake recv: {e}")
            return 'logout'
        if not ack:
            print("[ERROR] No response during handshake. File Server may be down.")
            return 'logout'
        if ack != b"HELLO":
            print(f"[ERROR] Unexpected handshake response: {ack}. Expected 'HELLO'")
            return 'logout'

        payload = {
            "command": "connect",
            "token": current_token.to_dict(),
            "signature": current_signature
        }
        file_sock.sendall(json.dumps(payload).encode())
        response = file_sock.recv(4096)

        if not response:
            print("[ERROR] No response from server. Connection may have failed.")
            return 'logout'

        res = json.loads(response.decode())
        print("[RESPONSE]", res)

    while True:
        print(f"\n[Using {'Group' if mode == 'group' else 'File'} Server as {current_token.username}]")
        print("-------- MENU --------")
        if mode == "group":
            print("1. Create User (Admin only)")
            print("2. Create Group")
            print("3. Add User to Group")
            print("4. List Group Members")
            print("5. List My Groups")
        elif mode == "file":
            print("7. Upload File")
            print("8. Download File")
        print("9. Logout and return to server selection")
        print("----------------------")

        choice = input("Enter your choice: ").strip()

        if choice == '9':
            print(f"[LOGOUT] Logging out {current_token.username}...")
            return 'logout'

        if mode == "group":
            if choice == '1':
                if current_token.username != "admin":
                    print("[ACCESS DENIED] Only the admin user can create accounts.")
                    continue
                username = input("Enter new username to create: ").strip()
                password = getpass.getpass("Enter password for new user: ").strip()
                res = send_request(group_sock, {
                    "command": "createUser",
                    "username": username,
                    "password": password,
                    "token": current_token.to_dict(),
                    "signature": current_signature
                })
                if res.get("status"):
                    print(f"[SUCCESS] User '{username}' created.")
                else:
                    print("[ERROR]", res.get("reason"))

            elif choice == '2':
                groupname = input("Enter new group name: ").strip()
                res = send_request(group_sock, {
                    "command": "createGroup",
                    "groupname": groupname,
                    "owner": current_token.username,
                    "token": current_token.to_dict(),
                    "signature": current_signature
                })
                if res.get("status"):
                    print(f"[SUCCESS] Group '{groupname}' created.")
                else:
                    print("[ERROR]", res.get("reason"))

            elif choice == '3':
                groupname = input("Enter group name: ").strip()
                username = input("Enter username to add: ").strip()
                res = send_request(group_sock, {
                    "command": "addUserToGroup",
                    "groupname": groupname,
                    "username": username,
                    "token": current_token.to_dict(),
                    "signature": current_signature
                })
                if res.get("status"):
                    print(f"[SUCCESS] User '{username}' added to group '{groupname}'.")
                else:
                    print("[ERROR]", res.get("reason"))

            elif choice == '4':
                groupname = input("Enter group name to list members: ").strip()
                res = send_request(group_sock, {
                    "command": "listGroupMembers",
                    "groupname": groupname,
                    "token": current_token.to_dict(),
                    "signature": current_signature
                })
                if res.get("status"):
                    members = res.get("members", [])
                    print(f"[MEMBERS of {groupname}]:", ', '.join(members) if members else "No members found.")
                else:
                    print("[ERROR]", res.get("reason"))

            elif choice == '5':
                res = send_request(group_sock, {
                    "command": "listMyGroups",
                    "token": current_token.to_dict(),
                    "signature": current_signature
                })
                if res.get("status"):
                    groups = res.get("groups", [])
                    print(f"[GROUPS for {current_token.username}]:", ', '.join(groups) if groups else "No groups found.")
                else:
                    print("[ERROR]", res.get("reason"))

            else:
                print("[ERROR] Invalid input.")

        elif mode == "file":
            if choice == '7':
                upload_file(file_sock, current_token, current_signature)
            elif choice == '8':
                download_file(file_sock, current_token, current_signature)
            else:
                print("[ERROR] Invalid input.")

def main():
    SERVER_IP = "11.22.56.67"
    group_addr = (SERVER_IP, 8000)
    file_addr = (SERVER_IP, 9000)

    current_token = None
    current_signature = None
    group_sock = None
    file_sock = None

    while True:
        print("\n==== SERVER SELECTION ====")
        print("1. Group Server")
        print("2. File Server")
        print("3. Exit")
        choice = input("Select a server: ").strip()

        if choice == '1':
            if not group_sock:
                group_sock = connect(*group_addr)
                if not group_sock:
                    print("[Error] Could not connect to Group Server.")
                    continue

            while not current_token:
                username = input('Enter username to log in: ')
                password = getpass.getpass('Enter password: ')
                res = send_request(group_sock, {
                    'command': 'getToken',
                    'username': username,
                    'password': password
                })
                token_data = res.get('token')
                signature = res.get('signature')
                if token_data and signature and verify_token(token_data, signature):
                    current_token = Token.from_dict(token_data)
                    current_signature = signature
                    save_session(username, token_data, signature)
                    print(f'[LOGIN SUCCESSFUL] Welcome, {current_token.username}')
                    print(f'[TOKEN VERIFIED] Groups: {current_token.groups}')
                else:
                    print('[Login Failed or Invalid Signature] Try again.')

            result = client_menu(group_sock=group_sock, file_sock=None, current_token=current_token, current_signature=current_signature)
            if result == 'logout':
                current_token = None

        elif choice == '2':
            session_user = input("Enter your username to resume session: ").strip()
            session_pass = getpass.getpass("Enter your password: ").strip()
            loaded = load_session(session_user)
            if not loaded:
                print("[Error] No valid session found. Please log in through the Group Server.")
                continue
            # Optional: basic password check simulation (not secure validation, just logging)
            print(f"[INFO] Password entered for {session_user}: (hidden)")
            if not loaded:
                print("[Error] No valid session found. Please log in through the Group Server.")
                continue

            current_token, current_signature = loaded

            if not file_sock:
                file_sock = connect(*file_addr)
                if not file_sock:
                    print("[Error] Could not connect to File Server.")
                    continue

            result = client_menu(group_sock=None, file_sock=file_sock, current_token=current_token, current_signature=current_signature)
            if result == 'logout':
                current_token = None

        elif choice == '3':
            print("Goodbye!")
            break

        else:
            print("[Error] Invalid selection.")

if __name__ == "__main__":
    main()
