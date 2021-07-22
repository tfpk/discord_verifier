echo -n "What is the arc key? "
read arc_key
export arc_key

echo -n "What is the short name? "
read short_name
export short_name

python3 - << EOF
import os
import edar
import secrets
from pathlib import Path

p = Path(os.environ['short_name'])

arc_token = os.environ['arc_key'].encode('utf-8')
print("Arc token: ", arc_token)
edar.create_key(p / 'arc_key.pem', arc_token)

key = edar.load_key(p / 'arc_key.pem', arc_token)

sub_token = secrets.token_urlsafe(32).encode('utf-8')
print("Subscriber token: ", sub_token)
edar.dump_key(p / 'sub_key.pem', key, sub_token)
EOF
