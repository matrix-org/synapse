from socket import socket
from urllib.parse import quote
from json import dumps, loads

class request():
	def __init__(self, config):
		self.conf = config
		self.s = socket()

	def build_header(self, h):
		s = ''
		for key, val in h.items():
			s += str(key) + ': ' + str(val) + '\r\n'
		return s + '\r\n'

	def build_request(self, _t, url, headers={}):
		while url[0] in ('.', '/'):
			url = url[1:]
		## Build the first line of the HTTP request:
		## <TYPE> /url?obj=val HTTP/1.1\r\n
		header = ''
		for key, val in headers.items():
			header += '&' + quote(key) + '=' + quote(val) # Adding the & at the front is kinda "risky",
								      # But the access token should always be there so.
		return '{} {}{} HTTP/1.1\r\n'.format(_t, 
							quote(self.conf['api']['base_url']+url),
							'?access_token=' + self.conf['api']['access_token'] + header)

	def parse_http(self, data):
		headers = {}

		head, payload = data.split(b'\r\n\r\n', 1)
		response, head = head.split(b'\r\n', 1)

		for obj in head.split(b'\r\n'):
			if len(obj) <= 0: continue
			key, val = obj.split(b':',1)
			headers[key.strip().lower()] = val.strip()

		if b'content-type' in headers and headers[b'content-type'] == b'application/json':
			payload = loads(payload.decode('UTF-8'))

		return int(response.split(b' ')[1]), headers, payload

	def send(self, _t, url, payload=None, headers={}):
		if payload:
			jdict = dumps(payload)
		else:
			jdict = ''

		h = {}
		h['Content-Length'] = len(jdict)
		h['Host'] = self.conf['homeserver'] + ':' + str(self.conf['hs_port'])
		h['Accept'] = 'application/json'
		h['Content-Type'] = 'application/json'
		h['Connection'] = 'close'

		data = bytes(self.build_request(_t, url, headers) + self.build_header(h) + jdict, 'UTF-8')
		print('Response:', data)

		self.s.connect((self.conf['homeserver'], self.conf['hs_port']))
		self.s.send(data)

	def recv(self, buffer=8192):
		return self.parse_http(self.s.recv(buffer))