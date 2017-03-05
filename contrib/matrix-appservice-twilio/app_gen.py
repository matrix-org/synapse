import hashlib
import time
import os
from base64 import b64encode as benc

m = hashlib.sha256()
m.update(benc(os.urandom(64)) + b'id' + bytes(str(time.time()), 'UTF-8'))
print('id:', m.hexdigest())

m = hashlib.sha256()
m.update(benc(os.urandom(64)) + b"smsGateway" + bytes(str(time.time()), 'UTF-8') + b'hs')
print('hs_token:', m.hexdigest())

m = hashlib.sha256()
m.update(benc(os.urandom(64)) + b"as" + bytes(str(time.time()), 'UTF-8') + b'smsGateway')
print('as_token:', m.hexdigest())

print('''namespaces:
  users:
    - exclusive: true
      regex: '@sms_.*:matrix\.domain\.com'
  aliases:
    - exclusive: true
      regex: '#sms_.*:matrix\.domain\.com'
  rooms:
    - exclusive: false
      regex: '!lEsjTTtbVuKfpEhxtT:matrix.domain.com'
url: 'http://127.0.0.1:9999
sender_localpart: twilio
rate_limited: false
''')
