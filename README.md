# Discord Verifier

This is a service that lets societies manage discord signups.

It's designed to be hosted on a CSE CGI server, currently at
https://web.cse.unsw.edu.au/~apps/discord/

This version is intended to be public, so it's missing two
files:

 - `env.sh` is a file that's hard coded to exist. It should look
   like the following (it just sets n environment variable and then
   runs python.

```
#!/bin/sh

# Your bot key
export DISCORD_BOT_KEY="Nz..aZ"

/web/cs1511/bin/python3 "$@"
```

 - `login_function.py` is a python file that should contain the function
   `authenticate(username: str, passsword: str) -> Optional[Dict[str, str]]`.
   if the authentication was successful, return a dict with a 'name' and 'email',
   otherwise return None. This code won't be made public, because that seems like
   a bad idea.

## Subdirectories

To add a new server, create a subfolder that looks like:

```
csesoc
├── admin.html -> ../admin.html
├── admins.json [should be a json array of zids]
├── brand.html [a html chunk to get inserted into the form]
├── index.html -> ../verify.html
├── students.csv [gets created automatically]
├── role_name.txt [name of the role this server uses when verified]
├── rules.html [a html chunk to get inserted into the "rules" section]
├── server.txt [the id of the server]
```

## Usage

Students go to `index.html` and follow the process there to verify.
Admins go to `admin.html` to setup the server.

## Note

This is one massive hack. I think I accidentally a monad somewhere in
my javascript, and it really should be burned to the ground. Sorry?
