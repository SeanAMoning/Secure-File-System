# =============================
# GroupServer
# =============================

import socket
import threading
import json
import os
import hmac
import hashlib
import base64
import time
from datetime import datetime

SECRET_KEY = b'super_secret_key_for_hmac'

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

def verify_token(token_dict, hmac_sig):
    msg = json.dumps(token_dict, sort_keys=True).encode()
    expected_sig = hmac.new(SECRET_KEY, msg, hashlib.sha256).digest()
    return hmac.compare_digest(base64.b64encode(expected_sig).decode(), hmac_sig)

class GroupServer:
    def __init__(self, host='0.0.0.0', port=8000):
        self.host = host
        self.port = port
        self.user_passwords = {}
        self.user_groups = {}
        self.group_owners = {}

        admin_password_hash = hashlib.sha256("seaniscool".encode()).hexdigest()
        self.user_passwords["admin"] = admin_password_hash
        self.user_groups["admin"] = ["./ADMIN"]
        self.group_owners["./ADMIN"] = "admin"

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"[GroupServer] Listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                print(f"[GroupServer] Client connected: {addr}")
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        with conn:
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break

                    req = json.loads(data.decode())
                    res = self._process(req)
                    if res is not None:
                        conn.sendall(json.dumps(res).encode())

            except Exception as e:
                print(f"[Server Error] {str(e)}")

    def _process(self, req):
        cmd = req.get("command")

        token_data = req.get("token")
        hmac_sig = req.get("HMAC")

        if cmd != "getToken":
            if not token_data or not hmac_sig:
                return {"status": False, "reason": "missing token or HMAC"}

            if not verify_token(token_data, hmac_sig):
                return {"status": False, "reason": "invalid or forged token"}

            token = Token.from_dict(token_data)
            requester = token.username

        if cmd == "createUser":
            if requester != "admin":
                return {"status": False, "reason": "only the admin user can create accounts"}

            username = req.get("username")
            password = req.get("password")
            if username in self.user_passwords:
                return {"status": False, "reason": "user already exists"}

            hashed = hashlib.sha256(password.encode()).hexdigest()
            self.user_passwords[username] = hashed
            with open("passwords.txt", "a") as f:
                f.write(f"{username}: {hashed}\n")
            print(f"[USER CREATED] {username}")
            return {"status": True}

        if cmd == "createGroup":
            groupname = req.get("groupname")
            owner = req.get("owner")
            if groupname in self.group_owners:
                return {"status": False, "reason": "group already exists"}

            self.group_owners[groupname] = owner
            self.user_groups.setdefault(owner, []).append(groupname)
            print(f"[GROUP CREATED] {groupname} by {owner}")
            return {"status": True}

        if cmd == "addUserToGroup":
            groupname = req.get("groupname")
            username = req.get("username")

            if groupname not in self.group_owners:
                return {"status": False, "reason": "group does not exist"}

            if username not in self.user_passwords:
                return {"status": False, "reason": "user does not exist"}

            if requester != "admin" and groupname not in self.user_groups.get(requester, []):
                return {"status": False, "reason": "only admin or group members can add users"}

            if groupname not in self.user_groups.setdefault(username, []):
                self.user_groups[username].append(groupname)

            print(f"[USER ADDED] {username} added to {groupname} by {requester}")
            return {"status": True}

        if cmd == "listGroupMembers":
            groupname = req.get("groupname")
            members = [user for user, groups in self.user_groups.items() if groupname in groups]
            return {"status": True, "members": members}

        if cmd == "listMyGroups":
            username = token.username
            groups = self.user_groups.get(username, [])
            return {"status": True, "groups": groups}

        if cmd == "getToken":
            username = req.get("username")
            password = req.get("password")
            if username not in self.user_passwords:
                return {"status": False, "reason": "user not found"}

            hashed_input = hashlib.sha256(password.encode()).hexdigest()
            if hashed_input != self.user_passwords[username]:
                return {"status": False, "reason": "incorrect password"}

            groups = self.user_groups.get(username, [])
            token_obj = Token(username, groups, timestamp=time.time())
            token_dict = token_obj.to_dict()

            msg = json.dumps(token_dict, sort_keys=True).encode()
            hmac_sig = base64.b64encode(hmac.new(SECRET_KEY, msg, hashlib.sha256).digest()).decode()

            return {"status": True, "token": token_dict, "HMAC": hmac_sig}

        return {"status": False, "error": "Unknown command"}

if __name__ == "__main__":
    server = GroupServer()
    server.start()
    print("[GroupServer] Running...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[GroupServer] Shutting down.")