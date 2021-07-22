#!/web/apps/discord/env.sh

import csv
import datetime
import copy
import json
import time
import difflib
import os
import requests

from pathlib import Path

import edar
import login_function


from flask import jsonify, Flask, make_response, request, abort

assert os.getenv('DISCORD_BOT_KEY')

DISCORD = "https://discordapp.com/api/v8"

discord_session = requests.Session()
discord_session.headers.update({"Authorization": f"Bot {os.getenv('DISCORD_BOT_KEY')}"})

LIMIT_MEMBERS = 1000


def list_members(server):
    LIST_MEMBERS_ENDPOINT = DISCORD + f"/guilds/{server}/members?limit={LIMIT_MEMBERS}"
    members = []
    new_members = discord_session.get(LIST_MEMBERS_ENDPOINT).json()
    max_member = sorted([m["user"]["id"] for m in new_members])[-1]

    while new_members:
        members += new_members
        new_endpoint = LIST_MEMBERS_ENDPOINT + f"&after={max_member}"
        max_member = sorted([m["user"]["id"] for m in new_members])[-1]
        new_members = discord_session.get(new_endpoint).json()

    return members


def list_roles(server):
    LIST_ROLES_ENDPOINT = DISCORD + f"/guilds/{server}/roles"
    roles = discord_session.get(LIST_ROLES_ENDPOINT)
    roles.raise_for_status()
    return roles.json()


def get_verified_role(server, role_name):
    roles = list_roles(server)
    for role in roles:
        if role["name"].lower().strip() == role_name.lower().strip():
            return role
    raise ValueError("Could not find role")


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

    best_matches = difflib.get_close_matches(
        username_search, member_tags, 2, cutoff=0.6
    )
    if len(best_matches) != 1:
        return None

    member = members_dict[best_matches[0]]

    return member


def change_member(server, member_id, role_ids, rm_role_ids):
    text = ""
    for role_id in role_ids:
        ADD_USER_ENDPOINT = (
            DISCORD + f"/guilds/{server}/members/{member_id}/roles/{role_id}"
        )
        put = discord_session.put(ADD_USER_ENDPOINT)
        put.raise_for_status()
        text += put.text + "\n"

    for rm_role_id in rm_role_ids:
        RM_USER_ENDPOINT = (
            DISCORD + f"/guilds/{server}/members/{member_id}/roles/{rm_role_id}"
        )
        dlt = discord_session.delete(RM_USER_ENDPOINT)
        dlt.raise_for_status()
        text += dlt.text + "\n"

    return text


app = Flask(__name__)



def write_to_students(site, user_dict, discord_info):
    import fcntl

    raw_data = f"{time.time()},{user_dict['zid']},{user_dict['name']},{user_dict['email']},{discord_info['username']},{discord_info['id']}\n".encode(
        "utf-8"
    )
    encrypted_data = edar.encrypt(
        edar.load_public_key(Path(site) / "sub_key"), raw_data
    )
    with open(f"{site}/students.csv", "ab") as members_csv:
        try:
            fcntl.flock(members_csv, fcntl.LOCK_EX)
            members_csv.write(encrypted_data + b"\n")
        finally:
            fcntl.flock(members_csv, fcntl.LOCK_UN)


QUERY_STRUCTURE = {
    "data": ["zid", "zpass", "name", "email", "ok"],
    "discord": ["discord_username", "discord_id", "info", "confirm_terms", "ok"],
    "confirmation": ["ok"],
    "site": [],
}


def check_structure_or_400(response):
    for part in QUERY_STRUCTURE:
        if part not in response:
            abort(400)
        for field in QUERY_STRUCTURE[part]:
            if field not in response[part]:
                abort(400)


def get_admin_settings(site):
    return {
        "rules": (Path(site) / "rules.html").read_text(),
        "admin_rules": (Path("arc_admin") / "admin_rules.html").read_text(),
        "admins": json.loads((Path(site) / "admins.json").read_text()),
    }


def set_admin_settings(site, settings):
    (Path(site) / "rules.html").write_text(settings["rules"])
    if site == "arc_admin":
        (Path(site) / "admin_rules.html").write_text(settings["admin_rules"])
    try:
        (Path(site) / "admins.json").write_text(json.dumps(settings["admins"]))
    except:
        pass


def get_settings(site):
    rm_role_file = Path(site) / "rm_role_name.txt"
    rm_role_name = ""
    if rm_role_file.exists():
        rm_role_name = rm_role_file.read_text().strip()
    return {
        "role_name": (Path(site) / "role_name.txt").read_text().strip(),
        "rm_role_name": rm_role_name,
        "server": (Path(site) / "server.txt").read_text().strip(),
        "brand": (Path(site) / "brand.html").read_text(),
        "rules": (Path(site) / "rules.html").read_text(),
        "admins": json.loads((Path(site) / "admins.json").read_text()),
        "admin_rules": (Path("arc_admin") / "admin_rules.html").read_text(),
        "arc_admins": json.loads((Path("arc_admin") / "admins.json").read_text()),
    }


def set_settings(site, settings):
    (Path(site) / "rules.html").write_text(settings["rules"])
    try:
        (Path(site) / "admins.json").write_text(json.dumps(settings["admins"]))
    except:
        pass


USERNAME_ERROR = """
<p>We couldn't find your username! Please make sure:</p>
<ul>
    <li>You have joined the server already</li>
    <li>You typed your name correctly</li>
    <li>If you didn't include it, make sure you included the #number after the username!</li>
</ul>
"""

def is_site_verified(site, response):
    if not site.replace("_", "").isalnum() or not os.path.isdir(site):
        response["error"] = {
            "text": "The site you attempted to access has not been configured!"
        }
        time.sleep(1)
        return False

    return True


@app.route("/verify/", methods=["POST"])
def verify():
    response = copy.deepcopy(request.json.copy())

    site = response["site"]
    if not is_site_verified(site, response):
        return make_response(jsonify(response))

    settings = get_settings(site)
    VERIFIED_ROLE = get_verified_role(settings["server"], settings["role_name"])
    if settings["rm_role_name"]:
        RM_VERIFIED_ROLE = get_verified_role(
            settings["server"], settings["rm_role_name"]
        )
    else:
        RM_VERIFIED_ROLE = None

    ALREADY_VERIFIED = f"""
    Your discord account already has the role '{VERIFIED_ROLE['name']}'!<br/>
    If you believe there is an error, contact the server admin!
    """

    user = login_function.authenticate(
        response["login"]["zid"], response["login"]["zpass"]
    )
    response["login"]["ok"] = False
    response["discord"]["ok"] = False
    response["confirmation"]["ok"] = False
    response["error"] = None
    response["info"] = None

    if not user:
        response["error"] = {"text": "Your zid and zpass were not recognised!"}
        response["login"]["zpass"] = ""
        response["login"]["ok"] = False
        time.sleep(1)
    else:
        response["login"]["ok"] = True
        user_dict = {
            "zid": response["login"]["zid"],
            "name": user["name"],
            "email": user["email"],
        }
        response["login"].update(user_dict)

        discord_username = response["discord"].get("discord_username")
        if discord_username:
            discord_info = get_member(settings["server"], discord_username)
            if not discord_info:
                response["error"] = {"text": USERNAME_ERROR}
            elif VERIFIED_ROLE["id"] in discord_info["roles"]:
                response["error"] = {"text": ALREADY_VERIFIED}
            else:
                response["discord"]["info"] = discord_info
                response["discord"]["discord_id"] = discord_info["user"]["id"]
                response["discord"]["ok"] = True

                if (
                    response["confirmation"]["confirm_terms"]
                    and response["confirmation"]["confirm_details"]
                ):
                    response["confirmation"]["result"] = change_member(
                        settings["server"],
                        response["discord"]["discord_id"],
                        [VERIFIED_ROLE["id"]],
                        [RM_VERIFIED_ROLE["id"]] if RM_VERIFIED_ROLE else [],
                    )
                    write_to_students(site, user_dict, discord_info["user"])
                    response["confirmation"]["ok"] = True

    return make_response(jsonify(response))


def parse_students(text):
    from io import StringIO

    HEADERS = ["time", "zid", "name", "email", "username", "discord_id"]

    text = text.replace("\n\n", "\n")
    f = StringIO(text)
    reader = csv.reader(f, delimiter=",")
    data = []
    for row in reader:
        d = dict(zip(HEADERS, row))
        try:
            d["time"] = str(datetime.datetime.fromtimestamp(float(d["time"])))
        except:
            d["time"] = "could not read"
        data.append(d)

    return data


@app.route("/admin/", methods=["POST"])
def admin():
    response = copy.deepcopy(request.json.copy())
    response["settings"]["admins"] = [
        response["settings"].get("admin_1", ""),
        response["settings"].get("admin_2", ""),
    ]

    site = response["site"]
    if not is_site_verified(site, response):
        return make_response(jsonify(response))

    settings = get_settings(site)
    user = login_function.authenticate(
        response["login"]["zid"], response["login"]["zpass"]
    )
    response["login"]["ok"] = False
    response["error"] = None
    try:
        sub_key = edar.load_key(
            Path(site) / "sub_key", response["login"]["key"].encode("utf-8")
        )
    except:
        sub_key = None

    try:
        arc_key = edar.load_key(
            Path(site) / "arc_key", response["login"]["key"].encode("utf-8")
        )
    except:
        arc_key = None

    key = arc_key or sub_key

    if response["error"]:
        time.sleep(1)
    elif not user:
        response["error"] = {"text": "Your zid and zpass were not recognised!"}
        response["login"]["zpass"] = ""
        response["login"]["ok"] = False
        time.sleep(1)
    elif response["login"]["zid"] not in settings["admins"] + settings["arc_admins"] + [
        "z5205060"
    ]:
        response["error"] = {"text": "You are not an admin!"}
        response["login"]["zpass"] = ""
        response["login"]["ok"] = False
        time.sleep(1)
    elif not key:
        response["error"] = {
            "text": "Your key was either incorrect, or not configured."
        }
        time.sleep(1)
    else:
        response["login"]["ok"] = True
        user_dict = {
            "zid": response["login"]["zid"],
        }
        response["login"].update(user_dict)
        if response["settings"]["update"]:
            set_settings(site, response["settings"])
            response["info"] = {"text": "Settings Updated"}
        else:
            response["settings"].update(settings)
            response["settings"]["update"] = True
        admins = response["settings"]["admins"] + ["", ""]
        response["settings"]["admin_1"] = admins[0]
        response["settings"]["admin_2"] = admins[1]
        response["students"] = (
            b"\n".join(
                [
                    edar.decrypt(key, line)
                    for line in (Path(site) / "students.csv")
                    .read_bytes()
                    .split(b"\n")[:-1]
                ]
            )
        ).decode("utf-8")
        response["parsed_students"] = parse_students(response["students"])
        try:
            response["channels"] = list(list_roles(settings["server"]))
        except:
            response["channels"] = []
            response["error"] = {
                "text": "Could not get roles on the server! This may indicate a setup issue with your server ID."
            }
        response["settings"]["admins"] = json.dumps(response["settings"]["admins"])

    return make_response(jsonify(response))


@app.route("/arc/admin/", methods=["POST"])
def arc_admin():
    response = copy.deepcopy(request.json.copy())
    response["error"] = None
    try:
        response["settings"]["admins"] = json.loads(response["settings"]["admins"])
    except:
        if response["settings"]["update"]:
            response["error"] = {"text": "The admins list you sent was invalid!"}
            time.sleep(1)
            return make_response(jsonify(response))

    site = response["site"]
    if site != "arc_admin":
        response["error"] = {"text": "This endpoint is only allowed for Arc Staff!"}

    settings = get_admin_settings(site)
    user = login_function.authenticate(
        response["login"]["zid"], response["login"]["zpass"]
    )
    response["login"]["ok"] = False

    if response["error"]:
        time.sleep(1)
    elif not user:
        response["error"] = {"text": "Your zid and zpass were not recognised!"}
        response["login"]["zpass"] = ""
        response["login"]["ok"] = False
        time.sleep(1)
    elif response["login"]["zid"] not in settings["admins"] + ["z5205060"]:
        response["error"] = {"text": "You are not an admin!"}
        response["login"]["zpass"] = ""
        response["login"]["ok"] = False
        time.sleep(1)
    else:
        response["login"]["ok"] = True
        user_dict = {
            "zid": response["login"]["zid"],
        }
        response["login"].update(user_dict)
        if response["settings"]["update"]:
            set_admin_settings(site, response["settings"])
            response["info"] = {"text": "Settings Updated"}
        else:
            response["settings"].update(settings)
            response["settings"]["update"] = True
        response["settings"]["admins"] = json.dumps(response["settings"]["admins"])
        response["sites"] = [p.parent.stem for p in Path(".").glob("*/admin.html")]

    return make_response(jsonify(response))


if __name__ == "__main__":

    @app.route("/arc_admin/")
    def arc_admin_view():
        return Path('arc_admin.html').read_text()

    @app.route("/<site>/")
    def site_index(site):
        return Path('verify.html').read_text()

    @app.route("/<page>.html")
    def docs(page):
        return Path(page+'.html').read_text()

    @app.route("/<site>/admin.html")
    def site_admin(site):
        return Path('admin.html').read_text()

    app.run(port=8000, debug=True)
