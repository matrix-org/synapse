from socket import *
from json import dumps, loads
from threading import *
from time import sleep # TODO: Just for now. Replace with signal and sigint.
from twilio.rest import TwilioRestClient

from config import *
from matrix import *

## == I strongly suggest you use the SDK instead: https://github.com/matrix-org/matrix-python-sdk
##    I just tend to like doing things manually, teaches me more about the protocol etc.

# https://github.com/matrix-org/synapse/blob/master/synapse/handlers/profile.py
# https://matrix.org/blog/2015/03/02/introduction-to-application-services/
# https://matrix.org/docs/api/client-server/

events_parsed = {} # TODO: Only used because I haven't figured out a proper response to events yet.

def parse_events(headers, data, s):
	if 'events' in data:
		for event in data['events']:
			if 'event_id' in event:
				if event['event_id'] not in events_parsed:
					events_parsed[event['event_id']] = True
				else:
					print('Muting duplicate event')
					continue

			if 'content' in event:
				ec = event['content']
				if 'membership' in ec and ec['membership'] == 'join': continue

				if 'msgtype' in ec:
					if ec['body'][:4] == 'sms:':
						cmd, to, msg = ec['body'].split(' ', 2)
						if event['sender'] in c['misc']['allowed_users']:
							account_sid = c['twilio']['as']
							auth_token = c['twilio']['at']
							client = TwilioRestClient(account_sid, auth_token)

							message = client.messages.create(to=to, from_=c['twilio']['from'], body=msg)
							print('SMS sent to:', to)
						else:
							if c['main_room']:
								send(c['main_room'], 'You\'re not allowed to send sms.', '@'+c['user']+':'+c['domain'])

				print(ec)
			for key, val in event.items():
				print('  ' + str(key) + ': ' + str(val))

		s.send(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}')

class reciever(Thread):
	def __init__(self, conf):
		Thread.__init__(self)

		print('Listening for API callbacks')
		self.conf = conf
		self.s = socket()
		self.s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.s.bind((conf['callbacks'], conf['callback_port']))
		self.s.listen(4)

		self.alive = True
		self.start()

	def kill(self):
		self.alive = False
		self.s.close()

	def run(self):
		main = None
		for t in enumerate():
			if t.name == 'MainThread':
				main = t
				break

		while self.alive and main and main.isAlive():
			ns, na = self.s.accept()

			data = ns.recv(8192)

			header, data = data.split(b'\r\n\r\n',1)
			request, header = header.split(b'\r\n',1)

			headers = {}
			for obj in header.split(b'\r\n'):
				if b': ' in obj:
					key, val = obj.split(b': ',1)
					headers[key.strip().lower()] = val.strip()

			headers['request'] = request
			try:
				jdata = loads(data)
			except:
				print('Could not decode JSON data:', str([header]), str([data]))
				#ns.send(b'HTTP/1.1 404 Not Found\r\nDate: Sat, 04 Mar 2017 19:58:38 GMT\r\nConnection: close\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 153\r\nServer: TwistedWeb/16.6.0\r\n\r\n\n<html>\n  <head><title>404 - No Such Resource</title></head>\n  <body>\n    <h1>No Such Resource</h1>\n    <p>No such child resource.</p>\n  </body>\n</html>\n')
			parse_events(headers, jdata, ns)
			ns.close()

bg = reciever(c)

# register('twilio', display_name='Twilio SMS')
# join('!lEsjTTtbVuKfpEhxtT', '@twilio:'+c['domain'])
# send('!lEsjTTtbVuKfpEhxtT', 'testing', '@twilio:'+c['domain'])

register(c['user'], display_name='Twilio SMS')
if c['main_room']:
	join(c['main_room'], '@'+c['user']+':'+c['domain'])
	send(c['main_room'], 'I just woke up!', '@'+c['user']+':'+c['domain'])

try:
	while 1:
		sleep(0.25)
except:
	pass

bg.kill()
