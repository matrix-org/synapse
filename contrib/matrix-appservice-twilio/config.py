c = {}
c['homeserver'] = '127.0.0.1'
c['hs_port'] = 8008
c['domain'] = 'matrix.domain.com'
c['callbacks'] = '127.0.0.1'
c['callback_port'] = 9999 # Whatever port is defined in my_appservice.yaml (see app_gen.py)

c['user'] = 'twilio' # (must match app_gen.py)
c['main_room'] = '!lEsjTTtbVuKfpEhxtT' # The main room to hang around in, if None we won't join.

c['api'] = {}
c['api']['base_url'] = '/_matrix/'
c['api']['access_token'] = 'whatever app_gen.py spit out'
c['api']['apppli_token'] = 'whatever app_gen.py spit out'

c['twilio'] = {}
c['twilio']['as'] = "Account Sid from Twilio dash-board" #Account Sid
c['twilio']['at'] = "Auth Token from the Twilio dash-board"   #Auth Token
c['twilio']['from'] = "+46000000000" # The number you've locked in at Twilio

c['misc'] = {}
c['misc']['allowed_users'] = {'@anton:matrix.domain.com'} # If any, we'll only allow these to send sms.

## == Kids, if you've ever learned consistency thinking..
##    This is a prime example of what you should not do.
##    But if you've tought to be lazy, this is what you'll do anyway.
##
##    making the config truly global even in submodules:
__builtins__['c'] = c