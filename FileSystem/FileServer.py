# =============================
# FileServer
# =============================

import socket
import threading
import json
import os
import hmac
import hashlib
import base64
import time

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

class FileServer:
    def __init__(self, host='0.0.0.0', port=9000, storage_dir='file_storage'):
        self.host = host
        self.port = port
        self.storage_dir = storage_dir
        self.file_permissions = {}
        os.makedirs(storage_dir, exist_ok=True)

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"[FileServer] Listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                print(f"[FileServer] Client connected: {addr}")
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        with conn:
            try:
                hello = conn.recv(1024)
                print(f"[DEBUG] Received handshake: {hello}")
                if not hello or hello.strip() != b"HELLO":
                    print(f"[FileServer] Invalid handshake: {hello}. Closing connection.")
                    return
                conn.sendall(b"HELLO")

                while True:
                    data = conn.recv(4096)
                    if not data:
                        break

                    req = json.loads(data.decode())
                    res = self._process(req, conn)

                    if res is not None:
                        conn.sendall(json.dumps(res).encode())

            except Exception as e:
                print(f"[Server Error] {e}")

    def _process(self, req, conn):
        cmd = req.get("command")
        token_data = req.get("token")
        hmac_sig = req.get("HMAC")

        if cmd == "connect":
            return {"status": True}

        if not token_data or not hmac_sig:
            return {"status": False, "reason": "missing token or HMAC"}

        if not verify_token(token_data, hmac_sig):
            return {"status": False, "reason": "invalid or forged token"}

        token = Token.from_dict(token_data)
        username = token.username

        if cmd == "upload":
            group = req.get("group")
            filename = req.get("filename")
            filesize = req.get("filesize")

            if group not in token.groups:
                return {"status": False, "reason": "user not in group or group does not exist"}

            if not filename or filesize is None:
                return {"status": False, "reason": "missing file data"}

            filepath = os.path.join(self.storage_dir, filename)
            conn.sendall(json.dumps({"status": True}).encode())

            received = 0
            with open(filepath, 'wb') as f:
                while received < filesize:
                    chunk = conn.recv(min(65536, filesize - received))
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)

            self.file_permissions[filename] = group
            print(f"[UPLOAD SUCCESS] '{filename}' uploaded by {username} to group '{group}'")
            return None

        if cmd == "download":
            filename = req.get("filename")
            if filename not in self.file_permissions:
                return {"status": False, "reason": "file not found"}

            group = self.file_permissions[filename]
            if group not in token.groups:
                return {"status": False, "reason": "access denied"}

            filepath = os.path.join(self.storage_dir, filename)
            if not os.path.isfile(filepath):
                return {"status": False, "reason": "file missing"}

            filesize = os.path.getsize(filepath)
            conn.sendall(json.dumps({"status": True, "filesize": filesize}).encode())

            ack = conn.recv(1024)
            if ack.decode() != "READY":
                return None

            with open(filepath, 'rb') as f:
                while chunk := f.read(65536):
                    conn.sendall(chunk)

            print(f"[DOWNLOAD SUCCESS] '{filename}' sent to {username}")
            return None

        return {"status": False, "error": "Unknown command"}

if __name__ == "__main__":
    server = FileServer()
    server.start()
    print("[FileServer] Running...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[FileServer] Shutting down.")