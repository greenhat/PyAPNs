# PyAPNs 

A Python library for interacting with the Apple Push Notification service 
(APNs)

## Installation

Either download the source from GitHub or use easy_install:

    $ easy_install apns


## Sample usage

```python
from apns import APNs, Payload

apns = APNs(use_sandbox=True, cert_file='cert.pem', key_file='key.pem')

# Send a notification
token_hex = 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b87'
payload = Payload(alert="Hello World!", sound="default", badge=1)
apns.gateway_server.send_notification(token_hex, payload)

# Get feedback messages
for (token_hex, fail_time) in apns.feedback_server.items():
    # do stuff with token_hex and fail_time
```

## Send a notification in enhanced format
```python
from apns import APNs, Payload, APNResponseError
from datetime import datetime, timedelta

apns = APNs(use_sandbox=True, cert_file='cert.pem', key_file='key.pem', enhanced=True)

token_hex = 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b87'
payload = Payload(alert="Hello World!", sound="default", badge=1)
identifier = 1234
expiry = datetime.utcnow() + timedelta(30) # undelivered notification expires after 30 seconds

try:
    apns.gateway_server.send_notification(token_hex, payload, identifier, expiry)
except APNResponseError, err:
    # handle apn's error response
    # just tried notification is not sent and this response doesn't belong to that notification.
    # formerly sent notifications should to be looked up with err.identifier to find one which caused this error.
    # when error response is received, connection to APN server is closed.
```

For more complicated alerts including custom buttons etc, use the PayloadAlert 
class. Example:

```python
alert = PayloadAlert("Hello world!", action_loc_key="Click me")
payload = Payload(alert=alert, sound="default")
```

To send custom payload arguments, pass a dictionary to the custom kwarg
of the Payload constructor.

```python
payload = Payload(alert="Hello World!", custom={'sekrit_number':123})
```

## Additional layer for managed delivery 
by Denys Zadorozhnyi

Rather then writing every time code to deal with invalid tokens from APNS feedback service and deleting sent push notifications I've made an additional layer on top of PyAPNs. In order to use it you have to implement two abstract classes: one which will provide push notification from your datastore and will handle deletions and the other which will handle deletion of devices with invalid tokens in your datastore.
Also it works correctly with multiple application bundle id which you might want to use in order to support separate version for App Store, beta list distribution, etc ( more on how to organize that see at http://swwritings.com/post/2013-05-20-concurrent-debug-beta-app-store-builds ).

Here is the example of how to use it:

```python
...
from apns.apns import Payload
from apns.managed_delivery import PushNotification, PushNotificationsProvider, SpecificPushNotificationsProvider, PushNotificationRelay, send, AbstractPushNotificationStore, AbstractDeviceStore
...

__author__ = 'Denys Zadorozhnyi'

PN_EXPIRY_DAYS = 3

class DeviceStore(AbstractDeviceStore):
    def __init__(self):
        self.connection = pg_db_connection_from_url(SETTINGS['DATABASE_URI'])

    def delete_devices_with_tokens(self, tokens):
        assert len(tokens)
        try:
            log.info('deleting devices with tokens: %s', tokens)
            cur = self.connection.cursor()
            for t in tokens:
                cur.execute('DELETE FROM device WHERE id = %s', [t])
            self.connection.commit()
            cur.close()
        except Exception as e:
            log.exception(e)

    def close(self):
        self.connection.close()


class PushNotificationStore(AbstractPushNotificationStore):
    def __init__(self):
        mongo_host = SETTINGS['MONGODB_PN_HOST']
        log.info('Connecting to MongoDB on %s', mongo_host)
        self.conn = MongoClient(mongo_host, SETTINGS['MONGODB_PN_PORT'])
        self.db = self.conn[SETTINGS['MONGODB_PN_DBNAME']]
        self.mongo_ids = {}

    def get_push_notifications(self):
        notifications = []
        raw_notifications = self.db.pending_push_notifications.find().sort('date_created')
        for n in raw_notifications:
            token = n['token']
            payload = Payload(alert=n.get('alert'),
                              custom=dict(et=n['event_type'], ep=n['event_param']))
            expiry = datetime.utcnow() + timedelta(days=PN_EXPIRY_DAYS)
            pn = PushNotification(token, payload, expiry, n['use_sandbox'], n['app_bundle_id'])
            notifications.append(pn)
            self.mongo_ids[pn.__repr__()] = n['_id']
        return notifications

    def delete_push_notifications(self, notifications):
        notification_ids = [self.mongo_ids[n.__repr__()] for n in notifications]
        log.info('deleting push notifications: %s', notifications)
        self.db.pending_push_notifications.remove({'_id': {'$in': notification_ids}})

    def close(self):
        self.conn.close()


def send_pn_for_app_bundle(bundle_id, device_store, is_sandbox, pn_provider):
    spec_pn_provider = SpecificPushNotificationsProvider(pn_provider, bundle_id, is_sandbox)
    cert, key = get_ssl_files(bundle_id, is_sandbox)
    relay = PushNotificationRelay(cert, key, is_sandbox)
    send(spec_pn_provider, device_store, relay)


def send_push_notifications():
    device_store = DeviceStore()
    pn_store = PushNotificationStore()
    pn_provider = PushNotificationsProvider(pn_store)
    for bundle_id in pn_provider.get_app_bundle_ids():
        if bundle_id == 'com.groceryxapp.1':
            send_for_app_bundle(bundle_id, device_store, False, pn_provider)
        if bundle_id == 'com.groceryxapp.1.adhoc':
            send_for_app_bundle(bundle_id, device_store, False, pn_provider)
        if bundle_id == 'com.groceryxapp.1.debug':
            send_for_app_bundle(bundle_id, device_store, True, pn_provider)
    pn_store.close()
    device_store.close()


```

## Prepare SSL certs
```bash
openssl pkcs12 -clcerts -nokeys -out cert.pem -in cert.p12
openssl pkcs12 -nocerts - nodes -out key.pem -in key.p12
```
via https://blog.serverdensity.com/how-to-build-an-apple-push-notification-provider-server-tutorial/


## Further Info

[iOS Reference Library: Local and Push Notification Programming Guide][a1]

## Credits

Written and maintained by Simon Whitaker at [Goo Software Ltd][goo].

[a1]:http://developer.apple.com/iphone/library/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Introduction/Introduction.html#//apple_ref/doc/uid/TP40008194-CH1-SW1
[goo]:http://www.goosoftware.co.uk/
