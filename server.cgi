#!/web/apps/discord/env.sh

from wsgiref.handlers import CGIHandler
from werkzeug.contrib.fixers import ProxyFix
from werkzeug.exceptions import HTTPException
from flask import request

from server import app

import traceback
import json
import datetime


def dump_error_obj(obj):
    obj["time"] = datetime.datetime.now().isoformat()
    with open("log.txt", "a") as log:
        log.write(json.dumps(obj, indent=2) + "\n=\n")

@app.errorhandler(Exception)
def error_handler(e):
    code = 500
    if isinstance(e, HTTPException):
        code = e.code

    data = request.json
    if "login" in data:
        data["zid"] = data["login"].get("zid")
        del data["login"]

    j = {
        "text": repr(e),
        "traceback": traceback.format_exc(),
        "code": data,
    }
    dump_error_obj(j)

    return "Internal Server Error. See Logs for more info.", code

if __name__ == "__main__":
    try:
        app.wsgi_app = ProxyFix(app.wsgi_app)  # Setup HTTP headers
        CGIHandler().run(app)
    except Exception as e:
        # catch any exceptions that escape Flask and print useful information
        print(
            "Content-Type: text/plain\nError occured which the server could not handle.",
            flush=True,
        )
        j = {"text": repr(e), "traceback": traceback.format_exc()}
        dump_error_obj(j)
