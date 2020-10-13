#!/web/apps/discord/env.sh
import csv
import copy
import json
import time
import difflib
import os
import sys
import requests
from pathlib import Path

"""
# Environment:

export DISCORD_BOT_KEY="Nz...M"
"""

import login_function


# CSESoc Verifier.

DISCORD = "https://discordapp.com/api/v8"

discord_session = requests.Session()
discord_session.headers.update({"Authorization": f"Bot {os.getenv('DISCORD_BOT_KEY')}"})


def list_members(server):
    LIST_MEMBERS_ENDPOINT = DISCORD + f"/guilds/{server}/members?limit=1000"
    return discord_session.get(LIST_MEMBERS_ENDPOINT).json()


def list_roles(server):
    LIST_ROLES_ENDPOINT = DISCORD + f"/guilds/{server}/roles"
    return discord_session.get(LIST_ROLES_ENDPOINT).json()


def get_verified_role(server, role_name):
    roles = list_roles(server)
    for role in roles:
        if role["name"].lower() == role_name.lower():
            return role
    

def reformat_member(member):
    user = member["user"]
    return (f"{user['username']}#{user['discriminator']}", member)


def get_member(server, username_search):
    members_dict = dict(map(reformat_member, list_members(server)))
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


def change_member(server, member_id, role_id):
    ADD_USER_ENDPOINT = (
        DISCORD + f"/guilds/{server}/members/{member_id}/roles/{role_id}"
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

def write_to_students(site, user_dict, discord_info):
    import fcntl
    with open(f"{site}/students.csv", "a") as members_csv:
        fcntl.flock(members_csv, fcntl.LOCK_EX)
        members_csv.write(f"{time.time()},{user_dict['zid']},{user_dict['name']},{user_dict['email']},{discord_info['username']},{discord_info['id']}\n")
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
   
def get_settings(site):
    return {
        'role_name': (Path(site) / 'role_name.txt').read_text().strip(),
        'server': (Path(site) / 'server.txt').read_text().strip(),
        'brand': (Path(site) / 'brand.html').read_text(),
        'rules': (Path(site) / 'rules.html').read_text(),
        'admins': json.loads((Path(site) / 'admins.json').read_text())
    }


def set_settings(site, settings):
    (Path(site) / 'role_name.txt').write_text(settings['role_name'])
    (Path(site) / 'server.txt').write_text(settings['server'])
    (Path(site) / 'brand.html').write_text(settings['brand'])
    (Path(site) / 'rules.html').write_text(settings['rules'])
    try:
        (Path(site) / 'admins.json').write_text(json.dumps(settings['admins']))
    except:
        pass

@app.route('/verify/', methods=['POST'])
def verify():
    response = copy.deepcopy(request.json.copy())
    site = response['site']
    if not site.isalnum() or not os.path.isdir(site):
        response['error'] = {"text": "The site you attempted to access has not been configured!"}
        time.sleep(1)
        return make_response(jsonify(response))

    settings = get_settings(site)
    VERIFIED_ROLE = get_verified_role(settings["server"], settings["role_name"])
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
        
    user = login_function.authenticate(response["login"]["zid"], response["login"]["zpass"])
    response["login"]["ok"] = False
    response["discord"]["ok"] = False
    response["confirmation"]["ok"] = False
    response["error"] = None
    response["info"] = None

    if not user:
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
            discord_info = get_member(settings["server"], discord_username)
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
                    response["confirmation"]["result"] = change_member(
                        settings["server"],
                        response["discord"]["discord_id"],
                        VERIFIED_ROLE["id"]
                    )
                    write_to_students(site, user_dict, discord_info["user"])
                    response["confirmation"]["ok"] = True


    return make_response(jsonify(response))

@app.route('/admin/', methods=['POST'])
def admin():
    response = copy.deepcopy(request.json.copy())
    try:
        response['settings']['admins'] = json.loads(response['settings']['admins'])
    except:
        if response['settings']['update']:
            response['error'] = {"text": "The admins list you sent was invalid!"}
            time.sleep(1)
            return make_response(jsonify(response))
    site = response['site']
    settings = get_settings(site)
    user = login_function.authenticate(response["login"]["zid"], response["login"]["zpass"])
    response["login"]["ok"] = False
    response["error"] = None

    if not site.isalnum() or not os.path.isdir(site):
        response['error'] = {"text": "The site you attempted to access has not been configured!"}
        time.sleep(1)
    elif not user:
        response['error'] = {"text": "Your zid and zpass were not recognised!"}
        response['login']['zpass'] = ''
        response['login']['ok'] = False
        time.sleep(1)
    elif response['login']['zid'] not in settings['admins']:
        response['error'] = {"text": "You are not an admin!"}
        response['login']['zpass'] = ''
        response['login']['ok'] = False
        time.sleep(1)
    else:
        response['login']['ok'] = True
        user_dict = {
            'zid': response["login"]["zid"],
        }
        response['login'].update(user_dict)
        if response['settings']['update']:
            set_settings(site, response['settings'])
            response["info"] = {"text": "Settings Updated"}
        else:
            response['settings'].update(settings)
            response['settings']['update'] = True
        response['students'] = (Path(site) / 'students.csv').read_text()
    
    return make_response(jsonify(response))

if __name__ == '__main__':
    app.wsgi_app = ProxyFix(app.wsgi_app) # Setup HTTP headers
    CGIHandler().run(app)
