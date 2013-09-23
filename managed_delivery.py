import abc
from apns import APNs
from apns import Payload
from apnserrors import InvalidTokenError, ShutdownError

__author__ = 'Denys Zadorozhnyi'


class PushNotification(object):
    def __init__(self, token, payload, expiry, use_sandbox, app_bundle_id):
        assert token
        assert payload
        assert isinstance(payload, Payload)
        assert expiry
        assert use_sandbox is not None
        self.token = token
        self.payload = payload
        self.expiry = expiry
        self.app_bundle_id = app_bundle_id
        self.use_sandbox = use_sandbox

    def __repr__(self):
        attrs = ("token", "payload", "expiry", "app_bundle_id", "use_sandbox")
        args = ", ".join(["%s=%r" % (n, getattr(self, n)) for n in attrs])
        return "%s(%s)" % (self.__class__.__name__, args)


class AbstractDeviceStore(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def delete_devices_with_tokens(self, tokens):
        """Method doc"""
        return


class AbstractPushNotificationStore(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_push_notifications(self):
        """Method documentation"""
        return

    @abc.abstractmethod
    def delete_push_notifications(self, notifications):
        """Method doc"""
        return


class PushNotificationsProvider(object):
    def __init__(self, store):
        assert isinstance(store, AbstractPushNotificationStore)
        self._store = store
        #noinspection PyNoneFunctionAssignment
        self._notifications = self._store.get_push_notifications()
        if self._notifications is None:
            self._notifications = []

    def get_app_bundle_ids(self):
        app_bundle_ids = set()
        for n in self._notifications:
            app_bundle_ids.add(n.app_bundle_id)
        return list(app_bundle_ids)

    def get_notifications(self, app_bundle_id, use_sandbox):
        return [n for n in self._notifications if
                (n.app_bundle_id == app_bundle_id and n.use_sandbox == use_sandbox)]

    def delete_notifications(self, notifications):
        self._notifications = [n for n in self._notifications if
                               n not in notifications]
        self._store.delete_push_notifications(notifications)


class SpecificPushNotificationsProvider(object):
    def __init__(self, provider, app_bundle_id, for_sandbox):
        self._provider = provider
        self._app_bundle_id = app_bundle_id
        self._for_sandbox = for_sandbox
        self._notifications = []
        self._load_notifications()

    def _load_notifications(self):
        self._notifications = self._provider.get_notifications(self._app_bundle_id,
                                                               self._for_sandbox)

    def get_notifications(self):
        return self._notifications

    def delete_notifications(self, notifications):
        if len(notifications):
            self._provider.delete_notifications(notifications)
            self._load_notifications()

    def delete_notifications_for_tokens(self, tokens):
        assert len(tokens)
        notifications_to_delete = [n for n in self._notifications if n.token in tokens]
        self.delete_notifications(notifications_to_delete)

    def delete_notifications_before_index(self, index):
        assert index
        notifications_before_index = []
        for i in range(0, len(self._notifications)):
            if i == index:
                break
            else:
                notifications_before_index.append(self._notifications[i])
        if len(notifications_before_index):
            self.delete_notifications(notifications_before_index)


class PushNotificationRelay(object):
    def __init__(self, ssl_cert, ssl_key, use_sandbox):
        # how to prepare the certs:
        # openssl pkcs12 -clcerts -nokeys -out cert.pem -in cert.p12
        # openssl pkcs12 -nocerts - nodes -out key.pem -in key.p12
        assert ssl_cert
        assert ssl_key
        self._ssl_cert = ssl_cert
        self._ssl_key = ssl_key
        self._use_sandbox = use_sandbox
        self._apns = None

    def connect(self):
        if self._apns:
            return
        self._apns = APNs(use_sandbox=self._use_sandbox, cert_file=self._ssl_cert,
                          key_file=self._ssl_key, enhanced=True)

    def get_invalid_tokens_from_feedback(self):
        assert self._apns
        invalid_tokens = [str(token_hex) for (token_hex, fail_time) in
                          self._apns.feedback_server.items()]
        invalid_tokens = list(set(invalid_tokens))
        return invalid_tokens if len(invalid_tokens) else None

    def send(self, notification, index):
        assert self._apns
        self._apns.gateway_server.send_notification(token_hex=notification.token,
                                                    payload=notification.payload,
                                                    identifier=index,
                                                    expiry=notification.expiry)


def send(pn_provider, device_store, pn_relay):
    assert isinstance(device_store, AbstractDeviceStore)
    assert isinstance(pn_provider, SpecificPushNotificationsProvider)
    assert isinstance(pn_relay, PushNotificationRelay)
    notifications = pn_provider.get_notifications()
    while len(notifications):
        pn_relay.connect()
        invalid_tokens = pn_relay.get_invalid_tokens_from_feedback()
        if invalid_tokens and len(invalid_tokens):
            device_store.delete_devices_with_tokens(invalid_tokens)
            pn_provider.delete_notifications_for_tokens(invalid_tokens)
            notifications = pn_provider.get_notifications()
        try:
            for i in range(0, len(notifications)):
                pn_relay.send(notifications[i], i)
        except InvalidTokenError as e:
            n_id = e.identifier + 1  # last success sent id is returned
            pn_provider.delete_notifications_before_index(n_id)
            invalid_token = notifications[n_id].token
            #log.info('APNS InvalidToken error returned notification id %s -> token %s',
            #         str(n_id), invalid_token)
            device_store.delete_devices_with_tokens([invalid_token])
            pn_provider.delete_notifications_for_tokens([invalid_token])
        except ShutdownError as e:
            n_id = e.identifier + 1  # last success sent id is returned
            pn_provider.delete_notifications_before_index(n_id)
            break
        else:
            pn_provider.delete_notifications_before_index(len(notifications))
        notifications = pn_provider.get_notifications()
