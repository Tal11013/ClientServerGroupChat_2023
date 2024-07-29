import socket
import threading
import atexit
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import pandas as pd
import os
import bcrypt

# a list that will hold the sockets of the client that are connected to the server
active_sockets = []

host = '127.0.0.1'
port = 12345

USER_ROLE = "user"
ADMIN_ROLE = "admin"

messages_folder = 'E:\\Project_dbs\\messages\\'
dbs_path = 'E:\\Project_dbs\\'
users_db = pd.read_csv(dbs_path + 'users_db.csv')
groups_db = pd.read_csv(dbs_path + 'groups_db.csv')

#an event that signals the shutdown of the server
shutdown = threading.Event()

# Generate a key and IV (Initialization Vector)
key = b'\x04\x03|\xeb\x8dSh\xe0\xc5\xae\xe5\xe1l9\x0co\xca\xb1"\r-Oo\xbaiYa\x1e\xd1\xf7\xa2\xdf'
iv = b'#\xb59\xee\xa7\xc4@n\xe5r\xac\x97lV\xff\xf1'


# Input: Takes plaintext as input.
# Output: Returns ciphertext after AES encryption with CBC mode and PKCS7 padding.
# the function encrypts the input plaintext using AES encryption with CBC mode and PKCS7 padding.
def encrypt(plaintext):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext


# Input: Takes ciphertext as input.
# Output: Returns decrypted plaintext.
# the function decrypts the input ciphertext using AES decryption with CBC mode and PKCS7 padding.
def decrypt(ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode('utf-8')


# Input: Takes a username and password as input.
# Output: Returns a boolean indicating authentication success and the user's role.
# the function reads the user database, checks if the username exists, and verifies the password using bcrypt hashing
# and returns the role of the user.
def authenticate_user(username, password):
    global users_db
    users_db = pd.read_csv(dbs_path + 'users_db.csv')
    # Check if username and password match any entry in the DataFrame
    match = users_db[(users_db['username'] == username)]
    if not match.empty:
        # Retrieve the stored hashed password from the database
        stored_hashed_password = match.iloc[0]['password']

        # Use bcrypt's checkpw function to compare the raw password with the stored hashed password
        if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
            return True, match.iloc[0]['role']

    return False, None


# Input: Takes a client socket as input.
# Output: None (void function).
# the function sends a menu to the client for options like login, register, change password, or exit,
# and routes the client accordingly.
def setup_client(client_socket):
    while True:
        client_socket.send(
            encrypt("choose an option between 1 and 3:\n1. Login.\n2. Register.\n3. Change your password \n4. Exit the server."))
        option = client_socket.recv(1024)
        option = decrypt(option)

        if option == "1":
            app_login(client_socket)
        elif option == "2":
            app_register(client_socket)
        elif option == "3":
            change_password(client_socket)
        elif option == "4":
            exit_app(client_socket)
        elif option == "":
            client_socket.close()
        else:
            client_socket.send(encrypt("The option you chose is not valid. choose from available options"))


# Input: Takes a client socket as input.
# Output: None (void function).
# The function prompts the user for username and password, authenticates the user, and handles login functionality.
def app_login(client_socket):
    global groups_db
    login_successful = False
    # Wait in the loop until the client gives the correct password and username
    while not login_successful and not shutdown.is_set():
        client_socket.send(encrypt("Type your username:"))
        username = client_socket.recv(1024)
        username = decrypt(username)
        client_socket.send(encrypt("Type your password:"))
        password = client_socket.recv(1024)
        password = decrypt(password)

        authenticated, role = authenticate_user(username, password)

        # if the password and username match
        if authenticated:
            client_ip, client_port = client_socket.getpeername()
            # Check if the username is in any group's participants list and if it is log in with a role
            user_row = groups_db[
                groups_db['Participants'].notna() & groups_db['Participants'].str.contains(username, case=False,
                                                                                           na=False)]
            if not user_row.empty:
                participants = eval(user_row.iloc[0]['Participants'])
                for participant in participants:
                    if participant['username'] == username:
                        participant['port'] = client_port
                groups_db.loc[user_row.index, 'Participants'] = str(participants)
                groups_db.to_csv(dbs_path + 'groups_db.csv', index=False)
            client_socket.send(encrypt(f"You are logged in as a {role}."))
            login_successful = True
            handle_client_requests(username, client_socket)
        else:
            client_socket.send(encrypt("Login error: check your username and password"))


# Input: Takes a client socket as input.
# Output: None (void function).
# The function prompts the user for a new username and password, hashes the password, and adds the user to the database.
# Also checks if the user is an admin
def app_register(client_socket):
    global users_db
    user_exists = True
    while user_exists and not shutdown.is_set():
        client_socket.send(encrypt("Type your new username:"))
        new_username = client_socket.recv(1024)
        new_username = decrypt(new_username)
        #check if the username already taken by someone else
        if new_username in users_db['username'].values:
            client_socket.send(encrypt("username is already taken, please choose another"))
        else:
            user_exists = False
            client_socket.send(encrypt("Type your new password:"))
            new_password = client_socket.recv(1024)
            new_password = decrypt(new_password)
            # Hash the password using bcrypt
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            hashed_password = hashed_password.decode('utf-8')
            # the username for admin:
            if new_username != "administrator110":
                new_user_data = pd.DataFrame({'username': [new_username], 'password': [hashed_password], 'role': [USER_ROLE]})
            else:
                new_user_data = pd.DataFrame({'username': [new_username], 'password': [hashed_password], 'role': [ADMIN_ROLE]})
            users_db = pd.concat([users_db, new_user_data], ignore_index=True)
            users_db.to_csv(dbs_path + 'users_db.csv', index=False)
            client_socket.send(encrypt("Registration successful."))
            handle_client_requests(new_username, client_socket)
            break


# Input: Takes a client socket as input.
# Output: None (void function).
# the function allows the user to change their password after authentication.
def change_password(client_socket):
    while True:
        client_socket.send(encrypt("What is your username?"))
        username = client_socket.recv(1024)
        username = decrypt(username)

        client_socket.send(encrypt("What is your current password?"))
        current_password = client_socket.recv(1024)
        current_password = decrypt(current_password)
        hashed_password = bcrypt.hashpw(current_password.encode('utf-8'), bcrypt.gensalt())
        hashed_password = hashed_password.decode('utf-8')
        authenticated, role = authenticate_user(username, hashed_password)
        if not authenticated:
            client_socket.send(encrypt("Invalid username or password. Please try again."))
            continue

        valid_password = False
        while not valid_password and not shutdown.is_set():
            client_socket.send(encrypt("What do you want your new password to be?"))
            changed_password = client_socket.recv(1024)
            changed_password = decrypt(changed_password)

            # check if the password is similar to the previous password
            if changed_password == current_password:
                client_socket.send(encrypt("Your new password cannot be similar to the previous one."))
            else:
                match = users_db[(users_db['username'] == username) & (users_db['password'] == current_password)]
                # Update the password for the matched user
                users_db.loc[match.index, 'password'] = changed_password
                users_db.to_csv(dbs_path + 'users_db.csv', index=False)
                client_socket.send(encrypt("Your new password is set."))
                handle_client_requests(username, client_socket)
                return


# Input: Takes a client socket and the group ID as input.
# Output: None (void function).
# the function displays all of the users that are connected to the group at that point and their roles.
def display_users(client_socket, group_id):
    global groups_db
    group_row = groups_db.loc[groups_db['GroupID'] == group_id]
    if not group_row.empty:
        participants = group_row.iloc[0]['Participants']
        # it is saved as a string in the CSV, so I evaluate the string to legal Python statement (list).
        if type(participants) == str:
            participants = eval(participants)


        # creating a list just for the sake of printing all the users in the group later
        users_with_roles = []
        for participant in participants:
            username = participant['username']
            role = users_db.loc[users_db['username'] == username, 'role'].iloc[0]
            users_with_roles.append((username, role))

        # printing all the users in the list
        user_info_str = '\n'.join([f"{username}: {role}" for username, role in users_with_roles])
        client_socket.send(encrypt(f"Users and roles connected to group {group_id}:\n{user_info_str}"))
    else:
        client_socket.send(encrypt("Group not found."))


# Input: Takes a client socket as input.
# Output: None (void function).
# the function shuts the connection between the server and client (in case client will decide to leave)
# and removes the client from the matching group.
def exit_app(client_socket):
    client_socket.send(encrypt("Disconnected successfully."))
    client_socket.close()


# Input: Takes a client socket and a username as input.
# Output: None (void function).
# the function differentiates between admins and users and provides each of them with the actions they have
# permissions for in this app.
def handle_client_requests(username, client_socket):
    global users_db
    role = users_db.loc[users_db['username'] == username, 'role'].iloc[0]
    if role == USER_ROLE:
        while True:
            client_socket.send(encrypt("What do you want to do?\n1. Join a group\n2. Create a group\n3. Exit"))
            option = client_socket.recv(1024)
            option = decrypt(option)

            if option == "1":
                join_group(username, client_socket)
            elif option == "2":
                create_group(username, client_socket)
            elif option == "3":
                exit_app(client_socket)
                break
            else:
                client_socket.send(encrypt("The option you chose is not valid. choose from available options"))
    elif role == ADMIN_ROLE:
        while True:
            client_socket.send(encrypt("What do you want to do?\n1. Join a group\n2. Create a group\n3. Ban a user\n4. Exit"))
            option = client_socket.recv(1024)
            option = decrypt(option)

            if option == "1":
                join_group(username, client_socket)
            elif option == "2":
                create_group(username, client_socket)
            elif option == "3":
                ban_user(client_socket)
            elif option == "4":
                exit_app(client_socket)
                break
            else:
                client_socket.send(encrypt("The option you chose is not valid. choose from available options"))


# Input: Takes a client socket as input.
# Output: None (void function).
# the function allows an admin to ban a user by removing them from the user database.
def ban_user(client_socket):
    while True:
        client_socket.send(encrypt("Type the username of the user you wish to ban:"))
        banned_username = client_socket.recv(1024)
        banned_username = decrypt(banned_username)

        match = users_db[(users_db['username'] == banned_username)]
        if match.empty:
            client_socket.send(encrypt("username does not exist. try again"))
        else:
            banned_user_role = match.iloc[0]['role']
            if banned_user_role == ADMIN_ROLE:
                client_socket.send(encrypt("you cannot this ban user - he is an admin"))
            else:
                users_db.drop(match.index, inplace=True)
                # Save the updated DataFrame to the CSV file
                users_db.to_csv(dbs_path + 'users_db.csv', index=False)
                client_socket.send(encrypt(f"User {banned_username} banned successfully."))
                break


# Input: Takes a username and client socket as input.
# Output: None (void function).
# The functions allows a user to join a group and handles client chat within the group.
# Also adds them to the group participants in the database.
def join_group(username, client_socket):
    global groups_db

    client_socket.send(encrypt("Enter the ID of the group you want to join:"))
    group_id = client_socket.recv(1024)
    group_id = decrypt(group_id)
    group_id = int(group_id)

    # Check if the group exists in the CSV file
    if group_id in groups_db['GroupID'].values:
        group_row = groups_db.loc[groups_db['GroupID'] == group_id]
        group_name = group_row.iloc[0]['GroupName']
        participants = group_row.iloc[0]['Participants']
        if type(participants) == str:
            participants = eval(participants)
        # Get the client's IP address and port
        client_ip, client_port = client_socket.getpeername()

        # Remove the user from all other groups (just another way to make sure the client can be connected
        # to one group at a time.
        for idx, row in groups_db.iterrows():
            if 'Participants' in row:
                participants_list = eval(row['Participants'])
                updated_participants = [p for p in participants_list if p['username'] != username]
                groups_db.loc[idx, 'Participants'] = str(updated_participants)

        groups_db.to_csv(dbs_path + 'groups_db.csv', index=False)

        # Construct a dictionary for the new participant
        new_participant = {'username': username, 'ip': client_ip, 'port': client_port}

        # Add the new participant's dictionary to the participants list
        participants.append(new_participant)

        # Update the participants list in memory and in the CSV
        filtered_rows = groups_db['GroupID'] == group_id
        participants_list = groups_db.loc[filtered_rows, 'Participants'].tolist()
        participants_list.append(new_participant)
        groups_db.loc[filtered_rows, 'Participants'] = str(participants)
        groups_db.to_csv(dbs_path + 'groups_db.csv', index=False)

        # Notify the user and broadcast the join message
        client_socket.send(encrypt(f"Connected to group {group_name}"))
        broadcast_message(f"{username} has joined the chat!", participants, client_socket)

        # Start handling client chat
        handle_client_chat(group_id, client_socket, username)
    else:
        client_socket.send(encrypt("Group not found. Please try again."))


# Input: Takes a username and client socket as input.
# Output: None (void function).
# the function allows a user to create a new group and handles client chat within the new
def create_group(username, client_socket):
    global groups_db
    client_socket.send(encrypt("Enter a name for the new group:"))
    group_name = client_socket.recv(1024)
    group_name = decrypt(group_name)
    client_socket.send(encrypt("Enter an ID for the new group:"))
    group_id = client_socket.recv(1024)
    group_id = decrypt(group_id)
    group_id = int(group_id)

    if group_id in groups_db['GroupID'].values:
        client_socket.send(encrypt("A group with the same ID already exists. Please choose another ID."))
        return

    client_ip, client_port = client_socket.getpeername()

    # Remove the user from all other groups (just another way to make sure the client can be connected
    # to one group at a time.
    for idx, row in groups_db.iterrows():
        if 'Participants' in row:
            participants_list = eval(row['Participants'])
            updated_participants = [p for p in participants_list if p['username'] != username]
            groups_db.loc[idx, 'Participants'] = str(updated_participants)

    groups_db.to_csv(dbs_path + 'groups_db.csv', index=False)

    # Add the user to the new group
    participants = [{'username': username, 'ip': client_ip, 'port': client_port}]
    new_group_data = {'GroupID': [group_id], 'GroupName': [group_name], 'Participants': [participants]}
    new_group_df = pd.DataFrame(new_group_data)
    existing_groups_df = pd.read_csv(dbs_path + 'groups_db.csv')
    groups_db = pd.concat([existing_groups_df, new_group_df], ignore_index=True)
    groups_db.to_csv(dbs_path + 'groups_db.csv', index=False)

    # Create a CSV file in the "messages" folder for this group
    os.makedirs(messages_folder, exist_ok=True)
    group_filename = f"{group_name}_{group_id}.csv"
    group_messages_path = os.path.join(messages_folder, group_filename)
    pd.DataFrame(columns=['Message']).to_csv(group_messages_path, index=False)

    client_socket.send(encrypt(f"Group '{group_name}' created successfully with ID {group_id}."))
    handle_client_chat(group_id, client_socket, username)


# Input: Takes a group ID, client socket, and username as input.
# Output: None (void function).
# The function handles client chat within a group, including sending and receiving messages or files,
# and displaying users connected.
def handle_client_chat(group_id, client_socket, username):
    global groups_db
    group_row = groups_db.loc[groups_db['GroupID'] == group_id]
    if not group_row.empty:
        participants = group_row.iloc[0]['Participants']
        if type(participants) == str:
            participants = eval(participants)

        message_count = 0
        start_time = time.time()
        while True:
            # if a minute has passed, start the count again
            if time.time() - start_time >= 60:
                message_count = 0
                start_time = time.time()

            client_socket.send(encrypt("What do you want to do?\n1. Send a message\n2. Send a file\n3. Display all users\n4. Exit group"))
            option = decrypt(client_socket.recv(1024))
            if option == "1":
                client_socket.send(encrypt("Type your message"))
                message = decrypt(client_socket.recv(1024))
                if message_count > 10:
                    client_socket.send(encrypt("You have reached the message limit for this session."))
                    continue
                broadcast_message(f"{username}: {message}", participants, client_socket)

                # adding the message to the csv file saving all the messages
                group_filename = f"{group_row.iloc[0]['GroupName']}_{group_id}.csv"
                group_messages_path = os.path.join(messages_folder, group_filename)
                pd.DataFrame({'Message': [f"{username}: {message}"]}).to_csv(group_messages_path, mode='a', header=False, index=False)

                message_count += 1

            elif option == "2":
                client_socket.send(encrypt("Enter the path of the file you want to send:"))
                file_path = decrypt(client_socket.recv(1024))

                if os.path.isfile(file_path):
                    file_name = os.path.basename(file_path)
                    file_size = os.path.getsize(file_path)
                    client_socket.send(encrypt(f"FILE: {file_name} ({file_size} bytes)"))

                    with open(file_path, 'rb') as file:
                        while True:
                            chunk = file.read(1024)
                            if not chunk:
                                break
                            client_socket.send(chunk)

                    broadcast_message(f"{username} sent a file: {file_name}", participants, client_socket)
                else:
                    client_socket.send(encrypt("File not found or invalid file path."))
            elif option == "3":
                display_users(client_socket, group_id)
            elif option == "4":
                participants = [p for p in participants if p['username'] != username]
                print(participants)
                groups_db.loc[group_row.index[0], 'Participants'] = str(participants)
                groups_db.to_csv(dbs_path + "groups_db.csv", index=False)
                client_socket.send(encrypt("You left the group, you are redirected to the menu"))
                handle_client_requests(username, client_socket)
                break

            else:
                client_socket.send(encrypt("Invalid option. Please choose again."))
    else:
        client_socket.send(encrypt("Group not found."))


# Input: Takes a message, list of participants, and sender socket as input.
# Output: None (void function).
# The function broadcasts a message to all participants in a group except the sender.
def broadcast_message(message, participants, sender_socket):
    try:
        for participant in participants:
            participant_ip = participant['ip']
            participant_port = participant['port']
            # I send a message to every participant in the group that is also active
            for socket in active_sockets:
                socket_ip, socket_port = socket.getpeername()
                if (participant_ip, participant_port) == (socket_ip, socket_port):
                    socket.send(encrypt(message))
    except Exception as e:
        print(f"Error occurred in broadcast_message: {e}")


# Input: None.
# Output: None (void function).
# The main function initializes the server, listens for incoming connections, and handles clients in separate threads.
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print('Server is listening for incoming connections...')

        while not shutdown.is_set():
            try:
                client_socket, address = server_socket.accept()
                print('Connected with', address)
                active_sockets.append(client_socket)
                threading.Thread(target=setup_client, args=(client_socket,)).start()
            except Exception as e:
                print("Error:", e)


# Input: None.
# Output: None (void function).
# The function stops the server and shuts down the program when called.
def stop_server():
    print("Shutting down server...")
    shutdown.set()


if __name__ == '__main__':
    atexit.register(stop_server)
    main()