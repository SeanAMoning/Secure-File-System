Instructions for Running the File Sharing System

1. Start the Servers:
Run the files called "FileServer.py" and "GroupServer.py" in separate terminals. This will start both the Group Server and the File Server.

2. Start the Client:
Open another terminal and run the file called "Cilent.py". This is the program you use to talk to the servers. Make sure the ip address of your computer is the same as the ip in the Client.py.  SERVER_IP = "11.22.56.67" -> or your ip address

3. Log in to Group Server:
Choose the Group Server option as you must login to group server before you can access the file server. Log in using the username "admin" and password "seaniscool". You need to do this first before using the File Server.

4. Create Users and Groups:
After logging in, you can create new users and groups. Only admin can create users. Group owners can add users to their groups.

5. Use the File Server:
To access the File Server press "9: Logout" and then "2: File Server". You will be asked to enter the password for the account you just logged out of ( "seaniscool").  After logging in you can now upload, download, or view files.

6. File Locations:
Uploaded files go into a folder called "file_storage" on the server. Downloaded files go into a folder called "downloads" with your username.

Important:
- Session.json shows token which has the username , group and timestamp. It also has the HMAC signature with the timestamp and expiration date.
- token_log shows the active token , who it was issued to and when it expires 
- test.txt is the file that is used to test the upload/download functionality
- You must log in to the Group Server before using the File Server.
- Make sure ports 8000 and 9000 are open.
- Everything must run on the same network or allow connections between computers.
- If running wireshark you have to use the loopback adapter and filter the results with "tcp.port == 8000 || tcp.port == 9000" . This will all communication to and from those ports



