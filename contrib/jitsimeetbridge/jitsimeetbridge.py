#!/usr/bin/env python

"""
This is an attempt at bridging matrix clients into a Jitis meet room via Matrix
video call.  It uses hard-coded xml strings overg XMPP BOSH. It can display one
of the streams from the Jitsi bridge until the second lot of SDP comes down and
we set the remote SDP at which point the stream ends. Our video never gets to
the bridge.

Requires:
npm install jquery jsdom
"""
import json
import subprocess
import time

import gevent
import grequests
from BeautifulSoup import BeautifulSoup

ACCESS_TOKEN = ""

MATRIXBASE = "https://matrix.org/_matrix/client/api/v1/"
MYUSERNAME = "@davetest:matrix.org"

HTTPBIND = "https://meet.jit.si/http-bind"
# HTTPBIND = 'https://jitsi.vuc.me/http-bind'
# ROOMNAME = "matrix"
ROOMNAME = "pibble"

HOST = "guest.jit.si"
# HOST="jitsi.vuc.me"

TURNSERVER = "turn.guest.jit.si"
# TURNSERVER="turn.jitsi.vuc.me"

ROOMDOMAIN = "meet.jit.si"
# ROOMDOMAIN="conference.jitsi.vuc.me"


class TrivialMatrixClient:
    def __init__(self, access_token):
        self.token = None
        self.access_token = access_token

    def getEvent(self):
        while True:
            url = (
                MATRIXBASE
                + "events?access_token="
                + self.access_token
                + "&timeout=60000"
            )
            if self.token:
                url += "&from=" + self.token
            req = grequests.get(url)
            resps = grequests.map([req])
            obj = json.loads(resps[0].content)
            print("incoming from matrix", obj)
            if "end" not in obj:
                continue
            self.token = obj["end"]
            if len(obj["chunk"]):
                return obj["chunk"][0]

    def joinRoom(self, roomId):
        url = MATRIXBASE + "rooms/" + roomId + "/join?access_token=" + self.access_token
        print(url)
        headers = {"Content-Type": "application/json"}
        req = grequests.post(url, headers=headers, data="{}")
        resps = grequests.map([req])
        obj = json.loads(resps[0].content)
        print("response: ", obj)

    def sendEvent(self, roomId, evType, event):
        url = (
            MATRIXBASE
            + "rooms/"
            + roomId
            + "/send/"
            + evType
            + "?access_token="
            + self.access_token
        )
        print(url)
        print(json.dumps(event))
        headers = {"Content-Type": "application/json"}
        req = grequests.post(url, headers=headers, data=json.dumps(event))
        resps = grequests.map([req])
        obj = json.loads(resps[0].content)
        print("response: ", obj)


xmppClients = {}


def matrixLoop():
    while True:
        ev = matrixCli.getEvent()
        print(ev)
        if ev["type"] == "m.room.member":
            print("membership event")
            if ev["membership"] == "invite" and ev["state_key"] == MYUSERNAME:
                roomId = ev["room_id"]
                print("joining room %s" % (roomId))
                matrixCli.joinRoom(roomId)
        elif ev["type"] == "m.room.message":
            if ev["room_id"] in xmppClients:
                print("already have a bridge for that user, ignoring")
                continue
            print("got message, connecting")
            xmppClients[ev["room_id"]] = TrivialXmppClient(ev["room_id"], ev["user_id"])
            gevent.spawn(xmppClients[ev["room_id"]].xmppLoop)
        elif ev["type"] == "m.call.invite":
            print("Incoming call")
            # sdp = ev['content']['offer']['sdp']
            # print "sdp: %s" % (sdp)
            # xmppClients[ev['room_id']] = TrivialXmppClient(ev['room_id'], ev['user_id'])
            # gevent.spawn(xmppClients[ev['room_id']].xmppLoop)
        elif ev["type"] == "m.call.answer":
            print("Call answered")
            sdp = ev["content"]["answer"]["sdp"]
            if ev["room_id"] not in xmppClients:
                print("We didn't have a call for that room")
                continue
            # should probably check call ID too
            xmppCli = xmppClients[ev["room_id"]]
            xmppCli.sendAnswer(sdp)
        elif ev["type"] == "m.call.hangup":
            if ev["room_id"] in xmppClients:
                xmppClients[ev["room_id"]].stop()
                del xmppClients[ev["room_id"]]


class TrivialXmppClient:
    def __init__(self, matrixRoom, userId):
        self.rid = 0
        self.matrixRoom = matrixRoom
        self.userId = userId
        self.running = True

    def stop(self):
        self.running = False

    def nextRid(self):
        self.rid += 1
        return "%d" % (self.rid)

    def sendIq(self, xml):
        fullXml = (
            "<body rid='%s' xmlns='http://jabber.org/protocol/httpbind' sid='%s'>%s</body>"
            % (self.nextRid(), self.sid, xml)
        )
        # print "\t>>>%s" % (fullXml)
        return self.xmppPoke(fullXml)

    def xmppPoke(self, xml):
        headers = {"Content-Type": "application/xml"}
        req = grequests.post(HTTPBIND, verify=False, headers=headers, data=xml)
        resps = grequests.map([req])
        obj = BeautifulSoup(resps[0].content)
        return obj

    def sendAnswer(self, answer):
        print("sdp from matrix client", answer)
        p = subprocess.Popen(
            ["node", "unjingle/unjingle.js", "--sdp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        jingle, out_err = p.communicate(answer)
        jingle = jingle % {
            "tojid": self.callfrom,
            "action": "session-accept",
            "initiator": self.callfrom,
            "responder": self.jid,
            "sid": self.callsid,
        }
        print("answer jingle from sdp", jingle)
        res = self.sendIq(jingle)
        print("reply from answer: ", res)

        self.ssrcs = {}
        jingleSoup = BeautifulSoup(jingle)
        for cont in jingleSoup.iq.jingle.findAll("content"):
            if cont.description:
                self.ssrcs[cont["name"]] = cont.description["ssrc"]
        print("my ssrcs:", self.ssrcs)

        gevent.joinall([gevent.spawn(self.advertiseSsrcs)])

    def advertiseSsrcs(self):
        time.sleep(7)
        print("SSRC spammer started")
        while self.running:
            ssrcMsg = (
                "<presence to='%(tojid)s' xmlns='jabber:client'><x xmlns='http://jabber.org/protocol/muc'/><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://jitsi.org/jitsimeet' ver='0WkSdhFnAUxrz4ImQQLdB80GFlE='/><nick xmlns='http://jabber.org/protocol/nick'>%(nick)s</nick><stats xmlns='http://jitsi.org/jitmeet/stats'><stat name='bitrate_download' value='175'/><stat name='bitrate_upload' value='176'/><stat name='packetLoss_total' value='0'/><stat name='packetLoss_download' value='0'/><stat name='packetLoss_upload' value='0'/></stats><media xmlns='http://estos.de/ns/mjs'><source type='audio' ssrc='%(assrc)s' direction='sendre'/><source type='video' ssrc='%(vssrc)s' direction='sendre'/></media></presence>"
                % {
                    "tojid": "%s@%s/%s" % (ROOMNAME, ROOMDOMAIN, self.shortJid),
                    "nick": self.userId,
                    "assrc": self.ssrcs["audio"],
                    "vssrc": self.ssrcs["video"],
                }
            )
            res = self.sendIq(ssrcMsg)
            print("reply from ssrc announce: ", res)
            time.sleep(10)

    def xmppLoop(self):
        self.matrixCallId = time.time()
        res = self.xmppPoke(
            "<body rid='%s' xmlns='http://jabber.org/protocol/httpbind' to='%s' xml:lang='en' wait='60' hold='1' content='text/xml; charset=utf-8' ver='1.6' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'/>"
            % (self.nextRid(), HOST)
        )

        print(res)
        self.sid = res.body["sid"]
        print("sid %s" % (self.sid))

        res = self.sendIq(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='ANONYMOUS'/>"
        )

        res = self.xmppPoke(
            "<body rid='%s' xmlns='http://jabber.org/protocol/httpbind' sid='%s' to='%s' xml:lang='en' xmpp:restart='true' xmlns:xmpp='urn:xmpp:xbosh'/>"
            % (self.nextRid(), self.sid, HOST)
        )

        res = self.sendIq(
            "<iq type='set' id='_bind_auth_2' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq>"
        )
        print(res)

        self.jid = res.body.iq.bind.jid.string
        print("jid: %s" % (self.jid))
        self.shortJid = self.jid.split("-")[0]

        res = self.sendIq(
            "<iq type='set' id='_session_auth_2' xmlns='jabber:client'><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>"
        )

        # randomthing = res.body.iq['to']
        # whatsitpart = randomthing.split('-')[0]

        # print "other random bind thing: %s" % (randomthing)

        # advertise preence to the jitsi room, with our nick
        res = self.sendIq(
            "<iq type='get' to='%s' xmlns='jabber:client' id='1:sendIQ'><services xmlns='urn:xmpp:extdisco:1'><service host='%s'/></services></iq><presence to='%s@%s/d98f6c40' xmlns='jabber:client'><x xmlns='http://jabber.org/protocol/muc'/><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://jitsi.org/jitsimeet' ver='0WkSdhFnAUxrz4ImQQLdB80GFlE='/><nick xmlns='http://jabber.org/protocol/nick'>%s</nick></presence>"
            % (HOST, TURNSERVER, ROOMNAME, ROOMDOMAIN, self.userId)
        )
        self.muc = {"users": []}
        for p in res.body.findAll("presence"):
            u = {}
            u["shortJid"] = p["from"].split("/")[1]
            if p.c and p.c.nick:
                u["nick"] = p.c.nick.string
            self.muc["users"].append(u)
        print("muc: ", self.muc)

        # wait for stuff
        while True:
            print("waiting...")
            res = self.sendIq("")
            print("got from stream: ", res)
            if res.body.iq:
                jingles = res.body.iq.findAll("jingle")
                if len(jingles):
                    self.callfrom = res.body.iq["from"]
                    self.handleInvite(jingles[0])
            elif "type" in res.body and res.body["type"] == "terminate":
                self.running = False
                del xmppClients[self.matrixRoom]
                return

    def handleInvite(self, jingle):
        self.initiator = jingle["initiator"]
        self.callsid = jingle["sid"]
        p = subprocess.Popen(
            ["node", "unjingle/unjingle.js", "--jingle"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        print("raw jingle invite", str(jingle))
        sdp, out_err = p.communicate(str(jingle))
        print("transformed remote offer sdp", sdp)
        inviteEvent = {
            "offer": {"type": "offer", "sdp": sdp},
            "call_id": self.matrixCallId,
            "version": 0,
            "lifetime": 30000,
        }
        matrixCli.sendEvent(self.matrixRoom, "m.call.invite", inviteEvent)


matrixCli = TrivialMatrixClient(ACCESS_TOKEN)  # Undefined name

gevent.joinall([gevent.spawn(matrixLoop)])
