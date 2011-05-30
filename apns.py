from binascii import a2b_hex, b2a_hex
from datetime import datetime
from socket import socket, AF_INET, SOCK_STREAM
from struct import pack, unpack

try:
    from ssl import wrap_socket
except ImportError:
    from socket import ssl

try:
    import json
except ImportError:
    import simplejson as json

GATEWAY_PORT = 2195
GATEWAY_HOST = 'gateway.push.apple.com'
GATEWAY_SANDBOX_HOST = 'gateway.sandbox.push.apple.com'

FEEDBACK_PORT = 2196
FEEDBACK_HOST = 'feedback.push.apple.com'
FEEDBACK_SANDBOX_HOST = 'feedback.sandbox.push.apple.com'

NOTIFICATION_COMMAND = 0

NOTIFICATION_FORMAT = (
    '!'   # network big-endian
    'B'   # command
    'H'   # token length
    '32s' # token
    'H'   # payload length
    '%ds' # payload
)

FEEDBACK_FORMAT = (
    '!'   # network big-endian
    'I'   # time
    'H'   # token length
    '32s' # token
)

FEEDBACK_FORMAT_LENGTH = 38 # struct.calcsize(FEEDBACK_FORMAT)
TOKEN_LENGTH = 32
MAX_PAYLOAD_LENGTH = 256


class APNs(object):
    """A class representing an Apple Push Notification service connection"""

    def __init__(self, use_sandbox=False, cert_file=None, key_file=None):
        """
        Set use_sandbox to True to use the sandbox (test) APNs servers.
        Default is False.
        """
        super(APNs, self).__init__()
        self.use_sandbox = use_sandbox
        self.cert_file = cert_file
        self.key_file = key_file
        self._feedback_connection = None
        self._gateway_connection = None

    @property
    def feedback_server(self):
        if not self._feedback_connection:
            self._feedback_connection = FeedbackConnection(
                use_sandbox = self.use_sandbox,
                cert_file = self.cert_file,
                key_file = self.key_file
            )
        return self._feedback_connection

    @property
    def gateway_server(self):
        if not self._gateway_connection:
            self._gateway_connection = GatewayConnection(
                use_sandbox = self.use_sandbox,
                cert_file = self.cert_file,
                key_file = self.key_file
            )
        return self._gateway_connection


class APNsConnection(object):
    """
    A generic connection class for communicating with the APNs
    """
    def __init__(self, cert_file=None, key_file=None):
        super(APNsConnection, self).__init__()
        self.cert_file = cert_file
        self.key_file = key_file
        self._socket = None
        self._ssl = None

    def __del__(self):
        self._disconnect();

    def _connect(self):
        # Establish an SSL connection
        self._socket = socket(AF_INET, SOCK_STREAM)
        self._socket.connect((self.server, self.port))
        if wrap_socket:
            self._ssl = wrap_socket(self._socket, self.key_file, self.cert_file)
        else:
            self._ssl = ssl(self._socket, self.key_file, self.cert_file)

    def _disconnect(self):
        if self._socket:
            self._socket.close()

    def _connection(self):
        if not self._ssl:
            self._connect()
        return self._ssl

    def read(self, n=None):
        return self._connection().read(n)

    def write(self, string):
        return self._connection().write(string)


class PayloadAlert(object):
    def __init__(self, body, action_loc_key=None, loc_key=None,
                 loc_args=None, launch_image=None):
        super(PayloadAlert, self).__init__()
        self.body = body
        self.action_loc_key = action_loc_key
        self.loc_key = loc_key
        self.loc_args = loc_args
        self.launch_image = launch_image

    def dict(self):
        d = { 'body': self.body }
        if self.action_loc_key:
            d['action-loc-key'] = self.action_loc_key
        if self.loc_key:
            d['loc-key'] = self.loc_key
        if self.loc_args:
            d['loc-args'] = self.loc_args
        if self.launch_image:
            d['launch-image'] = self.launch_image
        return d

class PayloadTooLargeError(Exception):
    def __init__(self):
        super(PayloadTooLargeError, self).__init__()

class Payload(object):
    """A class representing an APNs message payload"""
    def __init__(self, alert=None, badge=None, sound=None, custom={}):
        super(Payload, self).__init__()
        self.alert = alert
        self.badge = badge
        self.sound = sound
        self.custom = custom
        self._check_size()

    def dict(self):
        """Returns the payload as a regular Python dictionary"""
        d = {}
        if self.alert:
            # Alert can be either a string or a PayloadAlert
            # object
            if isinstance(self.alert, PayloadAlert):
                d['alert'] = self.alert.dict()
            else:
                d['alert'] = self.alert
        if self.sound:
            d['sound'] = self.sound
        if self.badge:
            d['badge'] = int(self.badge)

        d = { 'aps': d }
        d.update(self.custom)
        return d

    def json(self):
        return json.dumps(self.dict(), separators=(',',':'))

    def _check_size(self):
        if len(self.json()) > MAX_PAYLOAD_LENGTH:
            raise PayloadTooLargeError()

    def __repr__(self):
        attrs = ("alert", "badge", "sound", "custom")
        args = ", ".join(["%s=%r" % (n, getattr(self, n)) for n in attrs])
        return "%s(%s)" % (self.__class__.__name__, args)


class FeedbackConnection(APNsConnection):
    """
    A class representing a connection to the APNs Feedback server
    """
    def __init__(self, use_sandbox=False, **kwargs):
        super(FeedbackConnection, self).__init__(**kwargs)
        self.server = FEEDBACK_SANDBOX_HOST if use_sandbox else FEEDBACK_HOST
        self.port = FEEDBACK_PORT

    def _chunks(self):
        BUF_SIZE = 4096
        while 1:
            data = self.read(BUF_SIZE)
            yield data
            if not data:
                break

    def items(self):
        """
        A generator that yields (token_hex, fail_time) pairs retrieved from
        the APNs feedback server
        """
        buff = ''
        for chunk in self._chunks():
            buff += chunk

            # Quit if there's no more data to read
            if not buff:
                break

            # Sanity check: after a socket read we should always have at least
            # 6 bytes in the buffer
            if len(buff) < 6:
                break

            while len(buff) > 6:
                
                if len(buff) >= FEEDBACK_FORMAT_LENGTH:
                    
                    fail_time_unix, token_len, token = unpack(
                        FEEDBACK_FORMAT, buff[:FEEDBACK_FORMAT_LENGTH])

                    token_hex = b2a_hex(token)
                    fail_time = datetime.utcfromtimestamp(fail_time_unix)

                    yield (token_hex, fail_time)

                    # Remove data for current token from buffer
                    buff = buff[FEEDBACK_FORMAT_LENGTH:]
                else:
                    # break out of inner while loop - i.e. go and fetch
                    # some more data and append to buffer
                    break

class GatewayConnection(APNsConnection):
    """
    A class that represents a connection to the APNs gateway server
    """
    def __init__(self, use_sandbox=False, **kwargs):
        super(GatewayConnection, self).__init__(**kwargs)
        self.server = GATEWAY_SANDBOX_HOST if use_sandbox else GATEWAY_HOST
        self.port = GATEWAY_PORT

    def _get_notification(self, token_hex, payload):
        """
        Takes a token as a hex string and a payload as a Python dict and sends
        the notification
        """
        token = a2b_hex(token_hex)
        payload = payload.json()
        fmt = NOTIFICATION_FORMAT % len(payload)
        notification = pack(fmt, NOTIFICATION_COMMAND, TOKEN_LENGTH, token, 
                            len(payload), payload)
        return notification

    def send_notification(self, token_hex, payload):
        self.write(self._get_notification(token_hex, payload))

