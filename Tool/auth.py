import json
import os

USERS_FILE = "users.json"

def validate_user(username, password):
    if not os.path.exists(USERS_FILE):
        return False
    with open(USERS_FILE, "r") as f:
        users = json.load(f)
    return users.get(username) == password

def create_user(username, password):
    if not username or not password:
        return False
    users = {}
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            users = json.load(f)
    if username in users:
        return False  # user already exists
    users[username] = password
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)
    return True

def update_user(username, password):
    if not os.path.exists(USERS_FILE):
        return False
    with open(USERS_FILE, "r") as f:
        users = json.load(f)
    if username not in users:
        return False
    users[username] = password
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)
    return True
