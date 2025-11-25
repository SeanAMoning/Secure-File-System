# Secure File System Project

This project implements a distributed file system consisting of three major components: a Group Server, a File Server, and a Client. The system supports authenticated file sharing, secure group management, and controlled access to stored data.

The project was developed as part of a course focused on distributed architectures and secure communication. It demonstrates practical knowledge in networking, encryption concepts, client–server design, and access control.

---

## Project Overview

The distributed file system is designed to allow users to:

- Authenticate with a Group Server  
- Join or create groups for controlled access  
- Upload, download, delete, and list files stored on the File Server  
- Ensure operations are authorized using group membership and tokens  

The system uses two separate servers to divide responsibility:

- **GroupServer** – Handles users, authentication, group membership, and token issuance  
- **FileServer** – Stores and retrieves files, validating client tokens before allowing operations  

The client interacts with both servers to perform secure file operations.

---

## Project Structure

filesystem_project/
│── Cilent.py # Client interface for interacting with both servers
│── FileServer.py # Handles file operations and storage
│── GroupServer.py # Manages users, groups, and permission tokens
│── README.txt # Original notes included with the assignment
│── test.txt # Sample test file for upload/download operations


---

## Features

### User and Group Management
- User creation and authentication  
- Group creation and membership management  
- Token issuance for authorized access  

### File Operations
- Upload files  
- Download files  
- Delete files  
- List files stored on the server  

### Security Concepts
- Token-based authorization  
- Group-level access control  
- Separation of duties via multiple servers  

### Network Architecture
- Independent Group Server and File Server  
- Client communicates with each server over sockets  

---

## How the System Works

### Group Server
- Validates user login  
- Manages group creation/deletion  
- Adds or removes users from groups  
- Issues tokens that prove membership  
- Tokens must be presented to the File Server for file operations  

### File Server
- Verifies tokens from the Group Server  
- Checks permissions based on group membership  
- Performs file storage operations  
- Returns requested files or error responses  

### Client
- Authenticates with the Group Server  
- Sends tokens to the File Server for authorization  
- Provides user commands for file operations  

---

## Running the System

Start each component separately:

python3 GroupServer.py
python3 FileServer.py
python3 Cilent.py


The Group Server and File Server must be running before the Client connects.

---

## Requirements

- Python 3.x  
- Standard Python libraries (sockets, threading, etc.)  
- Ability to run multiple scripts simultaneously  

---

## Possible Improvements

The project can be enhanced in the future by adding:

- Stronger encryption mechanisms  
- Improved error handling  
- File versioning  
- Multi-client concurrency management  
- Persistent user/group storage  
- Configuration files for ports and settings  

---

## Status

Completed, with room for optional enhancements.

---

