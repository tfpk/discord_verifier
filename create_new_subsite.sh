#!/bin/sh

# Copy some defaults from this server
DEFAULT_SERVER="csesoc"

echo -n "What is the short name of this server: "
read short_name

[[ -d "$short_name" ]] && echo "The short name $short_name is in use!" && exit 1

install -d -m 755 $short_name

ln -s ../admin.html $short_name/admin.html
ln -s ../verify.html $short_name/index.html

cat $DEFAULT_SERVER/brand.html > $short_name/brand.html
chmod 644 $short_name/brand.html
cat $DEFAULT_SERVER/rules.html > $short_name/rules.html
chmod 644 $short_name/rules.html

echo -n "What is the server id for this server: "
read server_id

echo $server_id > $short_name/server.txt
chmod 600 $short_name/server.txt

echo -n "Who are the admins (json array): "
read admins

echo $admins > $short_name/admins.json
chmod 600 $short_name/admins.json

echo -n "What role name should be verified: "
read role_name

echo $role_name > $short_name/role_name.txt
chmod 600 $short_name/role_name.txt

touch $short_name/students.csv
chmod 600 $short_name/students.csv

echo -n "What is the arc key? "
read arc_key

# For use in the python script
export short_name
export arc_key

python3 - << EOF
import os
import edar
import secrets
from pathlib import Path

p = Path(os.environ['short_name'])

arc_token = os.environ['arc_key'].encode('utf-8')
print("Arc token: ", arc_token)
edar.create_key(p / 'arc_key', arc_token)

key = edar.load_key(p / 'arc_key.pem', arc_token)
sub_token = secrets.token_urlsafe(32).encode('utf-8')
print("Subscriber token: ", sub_token)
edar.dump_key(p / 'sub_key', key, sub_token)
EOF
