import json
import os
import edar
import secrets
import getpass

from pathlib import Path

TEMPLATE_BRAND = """\
<div class="m-3">
<h1>{full_name} Discord Verifier</h1>
</div>
<p>Please ensure you have joined the server!</p>%

"""

TEMPLATE_RULES = """\
  <p>Please accept the server rules:</p>
  <ol>
    <li>
      No NSFW content! Any form of pornography or nude imagery is not
      allowed on the server.
    </li>
    <li>
      Follow Discord Terms of Service! Please follow the Discord Terms
      of Service at all times while on the server.
      (https://discordapp.com/terms)
    </li>
    <li>
      No bad links! Any inappropriate links (phishy links, screamers,
      viruses or others) are not allowed on the server.
    </li>
    <li>
      Respect other people! Please be kind to one another. There is a
      border between jokes and harming someone's feelings, and it should
      not be crossed. Don't joke about disabilities.
    </li>
    <li>
      No hate speech This server is for everyone. No racist, sexist or
      homophobic slurs or any other form of hatred.
    </li>
    <li>
      Server admins have final verdict. The server admins are there for
      a reason. If they decide that something is disallowed, then it's
      disallowed.
    </li>
    <li>
      No Advertising! Any form of advertisement is not allowed on this
      server. Advertising discord server / youtube channel / twitch /
      twitter / other forms of media, that guides the user away from our
      server.
    </li>
    <li>Use common sense! Be nice to others</li>
  </ol>
  <p>
    Breach of any of these rules may result in a ban from our server and
    in serious cases, investigation into serious incidents by Arc UNSW.
    Note that while you are on the server, the UNSW Student Code applies
    to you as if you were on campus. We hope you have a good time on the
    server!
  </p>

"""

TEMPLATE_EMAIL = """\
Subject: Your Discord Verifier Has Now Been Configured
To: {primary_emails}
From: apps.discord@cse.unsw.edu.au
Bcc: z5205060@unsw.edu.au
Content-Type: text/plain

Dear {full_name} Server Admin,

Your Discord Verifier has now been configured!

You can find instructions on using your verifier here:
https://web.cse.unsw.edu.au/~apps/discord/documentation.html

The two pages you now have access to are:
For your users: https://web.cse.unsw.edu.au/~apps/discord/{{short_name}}/
For your admins: https://web.cse.unsw.edu.au/~apps/discord/{{short_name}}/admin.html

There are two important pieces of information you will need:
Your Short Code: {short_name}
Your Admin Key: {sub_token} (to log into your admin page)

Best,

~Tom Kunc
UNSW Discord Verifier Maintainer

"""


def create_subsite(
    short_name, full_name, server_id, role_name, admins_list, arc_key, contact
):
    admins = json.dumps(admins_list)
    site_path = Path(short_name)

    if site_path.is_dir():
        raise ValueError(f"Server called {short_name} already exists.")

    site_path.mkdir(mode=0o755)

    for link_file in ["admin.html", "index.html"]:
        (site_path / link_file).symlink_to("../" + link_file)

    # Configuration Files
    (site_path / "server.txt").write_text(server_id)
    (site_path / "server.txt").chmod(0o600)

    (site_path / "admins.json").write_text(admins)
    (site_path / "admins.json").chmod(0o600)

    (site_path / "role_name.txt").write_text(role_name)
    (site_path / "role_name.txt").chmod(0o600)

    # Data Files
    (site_path / "students.csv").touch(mode=0o600)

    # Keys
    edar.create_key(site_path / "arc_key", arc_key)

    key = edar.load_key(site_path / "arc_key.pem", arc_key)
    sub_key = secrets.token_urlsafe(32).encode("utf-8")
    print("Subscriber key: ", sub_key)
    edar.dump_key(site_path / "sub_key", key, sub_key)

    # Branding

    rules = TEMPLATE_RULES
    (site_path / "rules.html").write_text(rules)

    brand = TEMPLATE_BRAND.format(full_name=full_name)
    (site_path / "brand.html").write_text(brand)

    email = TEMPLATE_EMAIL.format(
        primary_emails=', '.join([contact] + [a + "@unsw.edu.au" for a in admins_list]),
        short_name=short_name,
        full_name=full_name,
        sub_token=sub_key.decode('utf-8'),
    )
    (site_path / "email.txt").write_text(email)
    print("Don't forget to email and destroy email.txt")

    return {
        'short_name': short_name,
        'sub_key': sub_key
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Create a subsite")

    parser.add_argument("short_name", type=str)
    parser.add_argument("full_name", type=str)
    parser.add_argument("server_id", type=str)
    parser.add_argument("role_name", type=str)
    parser.add_argument("admins_list", type=str)
    parser.add_argument("contact", type=str)

    args = parser.parse_args()

    admins_list = args.admins_list.split(",")

    arc_key = os.getenv("DISCORD_VERIFIER_ARC_KEY") or getpass.getpass("Arc Key: ")
    arc_key = arc_key.encode('utf-8')

    create_subsite(
        args.short_name,
        args.full_name,
        args.server_id,
        args.role_name,
        admins_list,
        arc_key,
        args.contact,
    )
