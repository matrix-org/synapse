from time import time

from webrequests import *

def register(username, display_name=None, auth={}):
	if not display_name: display_name = username

	connect = request(c)
	connect.send('POST', '/client/r0/register', payload={'auth' : auth, 'username' : username})
	rcode, headers, payload = connect.recv()

	if rcode == 200:
		print('Registration OK')
		connect = request(c)
		connect.send('PUT', '/client/r0/profile/@' + username + ':' + c['domain'] + '/displayname', payload={'displayname': display_name})

		rcode, headers, payload = connect.recv()
		return payload
	return payload

def room_mode(room, mode):
	#PUT /client/r0/directory/list/appservice/test.domain.com/!lEsjTTtbVuKfpEhxtT%3Amatrix.domain.com
	payload = {"visibility":"public"}

def send(room, message, user_id={}):
	connect = request(c)

	if type(user_id) != dict:
		user_id = {'user_id' : user_id}

	connect.send('PUT', '/client/r0/rooms/'+room+':'+c['domain']+'/send/m.room.message/m'+str(time()), {"msgtype":"m.text","body": message}, user_id)

	resp_code, headers, payload = connect.recv()
	return payload

def join(room, user_id={}):
	connect = request(c)

	if type(user_id) != dict:
		user_id = {'user_id' : user_id}

		connect.send('POST', '/client/r0/join/'+room+':'+c['domain'], {}, user_id)

	resp_code, headers, payload = connect.recv()
	return payload