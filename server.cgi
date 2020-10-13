#!/web/apps/discord/env.sh
import csv
import copy
import json
import time
import difflib
import pathlib
import os
import sys
import requests

"""
# Environment:

export DISCORD_BOT_KEY="Nz...M"
export DISCORD_SERVER="6...6"
export DISCORD_VERIFIED_ROLE_NAME="Verified"
"""

import login_function


# CSESoc Verifier.

DISCORD = "https://discordapp.com/api/v8"

discord_session = requests.Session()
discord_session.headers.update({"Authorization": f"Bot {os.getenv('DISCORD_BOT_KEY')}"})

DISCORD_SERVER = os.getenv("DISCORD_SERVER")


def list_members():
    LIST_MEMBERS_ENDPOINT = DISCORD + f"/guilds/{DISCORD_SERVER}/members?limit=1000"
    return discord_session.get(LIST_MEMBERS_ENDPOINT).json()


def list_roles():
    LIST_ROLES_ENDPOINT = DISCORD + f"/guilds/{DISCORD_SERVER}/roles"
    return discord_session.get(LIST_ROLES_ENDPOINT).json()


def get_verified_role():
    roles = list_roles()
    for role in roles:
        if role["name"].lower() == os.getenv("DISCORD_VERIFIED_ROLE_NAME").lower():
            return role

VERIFIED_ROLE = get_verified_role()

def reformat_member(member):
    user = member["user"]
    return (f"{user['username']}#{user['discriminator']}", member)


def get_member(username_search):
    members_dict = dict(map(reformat_member, list_members()))
    if "#" not in username_search:
        username_search += "#"
    member_tags = list(members_dict.keys())

    if username_search in member_tags:
        return members_dict[username_search]

    best_matches = difflib.get_close_matches(username_search, member_tags, 2, cutoff=0.6)
    if len(best_matches) != 1:
        return None

    member = members_dict[best_matches[0]]

    return member


def change_member(member_id):
    role_id = VERIFIED_ROLE["id"]
    ADD_USER_ENDPOINT = (
        DISCORD + f"/guilds/{DISCORD_SERVER}/members/{member_id}/roles/{role_id}"
    )

    put = discord_session.put(ADD_USER_ENDPOINT)
    return put.text

# Four states:
#  - Login (zid, zpass)
#  - Check Username ( + discord_username)
#  - Verify ( + discord_id, confirm_terms)

from wsgiref.handlers import CGIHandler
from werkzeug.contrib.fixers import ProxyFix

from flask import render_template, jsonify, Flask, make_response, request, abort

app = Flask(__name__)

def write_to_students(user_dict, discord_info):
    import fcntl
    with open("students.csv", "a") as members_csv:
        fcntl.flock(members_csv, fcntl.LOCK_EX)
        members_csv.write(f"{user_dict['zid']},{user_dict['name']},{user_dict['email']},{discord_info['username']},{discord_info['id']}\n")
        fcntl.flock(members_csv, fcntl.LOCK_UN)

QUERY_STRUCTURE = {
    "data": ["zid", "zpass", "name", "email", "ok"],
    "discord": ["discord_username", "discord_id", "info", "confirm_terms", "ok"],
    "confirmation": ["ok"],
    "site": []
}

def check_structure_or_400(response):
    for part in QUERY_STRUCTURE:
        if part not in response:
            abort(400)
        for field in QUERY_STRUCTURE[part]:
            if field not in response[part]:
                abort(400)
    

USERNAME_ERROR = """
<p>We couldn't find your username! Please make sure:</p>
<ul>
  <li>You have joined the server already</li>
  <li>You typed your name correctly</li>
  <li>If you didn't include it, make sure you included the #number after the username!</li>
</ul>
"""

ALREADY_VERIFIED = f"""
Your discord account already has the role '{VERIFIED_ROLE['name']}'!<br/>
If you believe there is an error, contact the server admin!
"""
        
@app.route('/verify/', methods=['POST'])
def verify():
    response = copy.deepcopy(request.json.copy())
    user = login_function.authenticate(response["login"]["zid"], response["login"]["zpass"])
    response["login"]["ok"] = False
    response["discord"]["ok"] = False
    response["confirmation"]["ok"] = False
    response["error"] = None

    if not response["site"].isalnum() or not os.path.isdir(response["site"]):
        response['error'] = {"text": "The site you attempted to access has not been configured!"}
        time.sleep(1)

    elif not user:
        response['error'] = {"text": "Your zid and zpass were not recognised!"}
        response['login']['zpass'] = ''
        response['login']['ok'] = False
        time.sleep(1)
    else:
        response['login']['ok'] = True
        user_dict = {
            'zid': response["login"]["zid"],
            'name': user["name"],
            'email': user["name"]
        }
        response['login'].update(user_dict)

        discord_username = response['discord'].get("discord_username")
        if discord_username:
            discord_info = get_member(discord_username)
            if not discord_info:
                response["error"] = {
                    "text": USERNAME_ERROR
                }
            elif VERIFIED_ROLE["id"] in discord_info["roles"]:
                response["error"] = {
                    "text": ALREADY_VERIFIED
                }
            else:
                response["discord"]["info"] = discord_info
                response["discord"]["discord_id"] = discord_info["user"]["id"]
                response["discord"]["ok"] = True

                if response["confirmation"]["confirm_terms"] and response["confirmation"]["confirm_details"]:
                    response["confirmation"]["result"] = change_member(response["discord"]["discord_id"])
                    write_to_students(user_dict, discord_info["user"])
                    response["confirmation"]["ok"] = True


    return make_response(jsonify(response))

if __name__ == '__main__':
    app.wsgi_app = ProxyFix(app.wsgi_app) # Setup HTTP headers
    CGIHandler().run(app)
