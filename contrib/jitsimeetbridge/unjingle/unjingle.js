var strophe = require("./strophe/strophe.js").Strophe;

var Strophe = strophe.Strophe;
var $iq     = strophe.$iq;
var $msg    = strophe.$msg;
var $build  = strophe.$build;
var $pres   = strophe.$pres;

var jsdom = require("jsdom");
var window = jsdom.jsdom().parentWindow;
var $ = require('jquery')(window);

var stropheJingle = require("./strophe.jingle.sdp.js");


var input = '';

process.stdin.on('readable', function() {
  var chunk = process.stdin.read();
  if (chunk !== null) {
    input += chunk;
  }
});

process.stdin.on('end', function() {
	if (process.argv[2] == '--jingle') {
		var elem = $(input);
		// app does:
		// sess.setRemoteDescription($(iq).find('>jingle'), 'offer');
		//console.log(elem.find('>content'));
		var sdp = new stropheJingle.SDP('');
		sdp.fromJingle(elem);
		console.log(sdp.raw);
	} else if (process.argv[2] == '--sdp') {
		var sdp = new stropheJingle.SDP(input);
		var accept = $iq({to: '%(tojid)s',
			type: 'set'})
			.c('jingle', {xmlns: 'urn:xmpp:jingle:1',
			    //action: 'session-accept',
			    action: '%(action)s',
			    initiator: '%(initiator)s',
			    responder: '%(responder)s',
			    sid: '%(sid)s' });
		sdp.toJingle(accept, 'responder');
		console.log(Strophe.serialize(accept));
	}
});

