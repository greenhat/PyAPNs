#!/usr/bin/env python
# coding: utf-8
from binascii import a2b_hex
from random import random
from datetime import datetime, timedelta
import hashlib
import time
import unittest

from apns import *
from managed_delivery import PushNotification, AbstractDeviceStore, AbstractPushNotificationStore, send, PushNotificationsProvider, SpecificPushNotificationsProvider, PushNotificationRelay
import mock

APP_BUNDLE_ID1 = 'com.app.1'
APP_BUNDLE_ID2 = 'com.app.2'

TEST_CERTIFICATE = "certificate.pem" # replace with path to test certificate

NUM_MOCK_TOKENS = 10
mock_tokens = []
for i in range(0, NUM_MOCK_TOKENS):
    mock_tokens.append(hashlib.sha256("%.12f" % random()).hexdigest())


def mock_chunks_generator():
    BUF_SIZE = 64
    # Create fake data feed
    data = ''

    for t in mock_tokens:
        token_bin = a2b_hex(t)
        token_length = len(token_bin)

        data += APNs.packed_uint_big_endian(int(time.time()))
        data += APNs.packed_ushort_big_endian(token_length)
        data += token_bin

    while data:
        yield data[0:BUF_SIZE]
        data = data[BUF_SIZE:]


class TestAPNs(unittest.TestCase):
    """Unit tests for PyAPNs"""

    def setUp(self):
        """docstring for setUp"""
        pass

    def tearDown(self):
        """docstring for tearDown"""
        pass

    def testConfigs(self):
        apns_test = APNs(use_sandbox=True)
        apns_prod = APNs(use_sandbox=False)

        self.assertEqual(apns_test.gateway_server.port, 2195)
        self.assertEqual(apns_test.gateway_server.server,
                         'gateway.sandbox.push.apple.com')
        self.assertEqual(apns_test.feedback_server.port, 2196)
        self.assertEqual(apns_test.feedback_server.server,
                         'feedback.sandbox.push.apple.com')

        self.assertEqual(apns_prod.gateway_server.port, 2195)
        self.assertEqual(apns_prod.gateway_server.server,
                         'gateway.push.apple.com')
        self.assertEqual(apns_prod.feedback_server.port, 2196)
        self.assertEqual(apns_prod.feedback_server.server,
                         'feedback.push.apple.com')

    def testGatewayServer(self):
        pem_file = TEST_CERTIFICATE
        apns = APNs(use_sandbox=True, cert_file=pem_file, key_file=pem_file)
        gateway_server = apns.gateway_server

        self.assertEqual(gateway_server.cert_file, apns.cert_file)
        self.assertEqual(gateway_server.key_file, apns.key_file)

        token_hex = 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'
        payload = Payload(
            alert="Hello World!",
            sound="default",
            badge=4
        )
        notification = gateway_server._get_notification(token_hex, payload)

        expected_length = (
            1                       # leading null byte
            + 2                     # length of token as a packed short
            + len(token_hex) / 2    # length of token as binary string
            + 2                     # length of payload as a packed short
            + len(payload.json())   # length of JSON-formatted payload
        )

        self.assertEqual(len(notification), expected_length)
        self.assertEqual(notification[0], '\0')

    def testEnhancedGatewayServer(self):
        pem_file = TEST_CERTIFICATE
        apns = APNs(use_sandbox=True, cert_file=pem_file, key_file=pem_file, enhanced=True)
        gateway_server = apns.gateway_server

        self.assertEqual(gateway_server.cert_file, apns.cert_file)
        self.assertEqual(gateway_server.key_file, apns.key_file)

        token_hex = 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'
        payload = Payload(
            alert="Hello World!",
            sound="default",
            badge=4
        )
        expiry = datetime.utcnow() + timedelta(30)
        notification = gateway_server._get_enhanced_notification(token_hex, payload, 0,
                                                                 expiry)

        expected_length = (
            1                       # leading null byte
            + 4                     # identifier as a packed int
            + 4                     # expiry as a packed int
            + 2                     # length of token as a packed short
            + len(token_hex) / 2    # length of token as binary string
            + 2                     # length of payload as a packed short
            + len(payload.json())   # length of JSON-formatted payload
        )

        self.assertEqual(len(notification), expected_length)
        self.assertEqual(notification[0], '\1')

    def testFeedbackServer(self):
        pem_file = TEST_CERTIFICATE
        apns = APNs(use_sandbox=True, cert_file=pem_file, key_file=pem_file)
        feedback_server = apns.feedback_server

        self.assertEqual(feedback_server.cert_file, apns.cert_file)
        self.assertEqual(feedback_server.key_file, apns.key_file)

        # Overwrite _chunks() to call a mock chunk generator
        feedback_server._chunks = mock_chunks_generator

        i = 0;
        for (token_hex, fail_time) in feedback_server.items():
            self.assertEqual(token_hex, mock_tokens[i])
            i += 1
        self.assertEqual(i, NUM_MOCK_TOKENS)

    def testPayloadAlert(self):
        pa = PayloadAlert('foo')
        d = pa.dict()
        self.assertEqual(d['body'], 'foo')
        self.assertFalse('action-loc-key' in d)
        self.assertFalse('loc-key' in d)
        self.assertFalse('loc-args' in d)
        self.assertFalse('launch-image' in d)

        pa = PayloadAlert('foo', action_loc_key='bar', loc_key='wibble',
                          loc_args=['king', 'kong'], launch_image='wobble')
        d = pa.dict()
        self.assertEqual(d['body'], 'foo')
        self.assertEqual(d['action-loc-key'], 'bar')
        self.assertEqual(d['loc-key'], 'wibble')
        self.assertEqual(d['loc-args'], ['king', 'kong'])
        self.assertEqual(d['launch-image'], 'wobble')

    def testPayload(self):
        # Payload with just alert
        p = Payload(alert=PayloadAlert('foo'))
        d = p.dict()
        self.assertTrue('alert' in d['aps'])
        self.assertTrue('sound' not in d['aps'])
        self.assertTrue('badge' not in d['aps'])

        # Payload with just sound
        p = Payload(sound="foo")
        d = p.dict()
        self.assertTrue('sound' in d['aps'])
        self.assertTrue('alert' not in d['aps'])
        self.assertTrue('badge' not in d['aps'])

        # Payload with just badge
        p = Payload(badge=1)
        d = p.dict()
        self.assertTrue('badge' in d['aps'])
        self.assertTrue('alert' not in d['aps'])
        self.assertTrue('sound' not in d['aps'])

        # Payload with just badge removal
        p = Payload(badge=0)
        d = p.dict()
        self.assertTrue('badge' in d['aps'])
        self.assertTrue('alert' not in d['aps'])
        self.assertTrue('sound' not in d['aps'])

        # Test plain string alerts
        alert_str = 'foobar'
        p = Payload(alert=alert_str)
        d = p.dict()
        self.assertEqual(d['aps']['alert'], alert_str)
        self.assertTrue('sound' not in d['aps'])
        self.assertTrue('badge' not in d['aps'])

        # Test custom payload
        alert_str = 'foobar'
        custom_dict = {'foo': 'bar'}
        p = Payload(alert=alert_str, custom=custom_dict)
        d = p.dict()
        self.assertEqual(d, {'foo': 'bar', 'aps': {'alert': 'foobar', 'content-available': 1}})


    def testPayloadTooLargeError(self):
        # The maximum size of the JSON payload is MAX_PAYLOAD_LENGTH 
        # bytes. First determine how many bytes this allows us in the
        # raw payload (i.e. before JSON serialisation)
        json_overhead_bytes = len(Payload('.').json()) - 1
        max_raw_payload_bytes = MAX_PAYLOAD_LENGTH - json_overhead_bytes

        # Test ascii characters payload
        Payload('.' * max_raw_payload_bytes)
        self.assertRaises(PayloadTooLargeError, Payload,
                          '.' * (max_raw_payload_bytes + 1))
        # Test unicode 2-byte characters payload
        Payload(u'\u0100' * int(max_raw_payload_bytes / 2))
        self.assertRaises(PayloadTooLargeError, Payload,
                          u'\u0100' * (int(max_raw_payload_bytes / 2) + 1))


#noinspection PyPropertyAccess
class TestManagedDelivery(unittest.TestCase):
    """Unit tests for PyAPNs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def testPushNotification(self):
        token_hex = 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'
        payload = Payload(alert='alert')
        pn = PushNotification(token=token_hex, payload=payload,
                              expiry=datetime.now() + timedelta(days=1), use_sandbox=True,
                              app_bundle_id='com.someapp')
        self.assertIsNotNone(pn)
        self.assertIn(token_hex, pn.__repr__())
        self.assertIn('alert', pn.__repr__())
        self.assertIn('com.someapp', pn.__repr__())

    #noinspection PyAttributeOutsideInit
    class MockPushNotificationStore(AbstractPushNotificationStore):

        def __init__(self):
            self.t_prefix = 1
            self._notifications = []
            self._notifications.append(self.generate_pn(True, APP_BUNDLE_ID1))
            self._notifications.append(self.generate_pn(True, APP_BUNDLE_ID1))
            self._notifications.append(self.generate_pn(False, APP_BUNDLE_ID1))
            self._notifications.append(self.generate_pn(False, APP_BUNDLE_ID1))

            self._notifications.append(self.generate_pn(True, APP_BUNDLE_ID2))
            self._notifications.append(self.generate_pn(True, APP_BUNDLE_ID2))
            self._notifications.append(self.generate_pn(False, APP_BUNDLE_ID2))
            self._notifications.append(self.generate_pn(False, APP_BUNDLE_ID2))
            self.deleted_notifications = []

        def generate_pn(self, use_sandbox, app_bundle_id):
            token = str(self.t_prefix) + \
                    '5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'
            notification = PushNotification(
                token=token,
                payload=(Payload(alert='Hello', custom=dict(et='LU', ep='npvskgdhlmcdkfgj'))),
                expiry=datetime.utcnow() + timedelta(days=3), use_sandbox=use_sandbox,
                app_bundle_id=app_bundle_id)
            self.t_prefix += 1
            return notification

        def get_push_notifications(self):
            return self._notifications

        def delete_push_notifications(self, notifications):
            self._notifications = [n for n in self._notifications if n not in notifications]
            self.deleted_notifications.extend(notifications)

    def test_no_notifications(self):
        mock_pn_store = self.MockPushNotificationStore()
        mock_pn_store._notifications = None
        pn_provider = SpecificPushNotificationsProvider(PushNotificationsProvider(mock_pn_store),
                                                        app_bundle_id=APP_BUNDLE_ID1,
                                                        for_sandbox=True)

        mock_device_store = mock.Mock()
        mock_device_store.__class__ = AbstractDeviceStore

        mock_apns = mock.Mock()
        mock_apns.feedback_server = mock.Mock()
        mock_apns.feedback_server.items.return_value = []
        mock_apns.gateway_server = mock.Mock()
        pn_relay = PushNotificationRelay('cert', 'key', True)
        pn_relay._apns = mock_apns

        send(pn_provider=pn_provider, device_store=mock_device_store, pn_relay=pn_relay)
        self.assertFalse(mock_apns.feedback_server.items.called)
        self.assertFalse(mock_apns.gateway_server.send_notification.called)
        self.assertFalse(mock_device_store.delete_devices_with_tokens.called)
        self.assertEqual(len(mock_pn_store.deleted_notifications), 0)

    def test_send_no_invalid_tokens(self):
        mock_pn_store = self.MockPushNotificationStore()
        pn_provider = SpecificPushNotificationsProvider(PushNotificationsProvider(mock_pn_store),
                                                        app_bundle_id=APP_BUNDLE_ID1,
                                                        for_sandbox=True)
        mock_device_store = mock.Mock()
        mock_device_store.__class__ = AbstractDeviceStore

        mock_apns = mock.Mock()
        mock_apns.feedback_server = mock.Mock()
        mock_apns.feedback_server.items.return_value = []
        mock_apns.gateway_server = mock.Mock()
        pn_relay = PushNotificationRelay('cert', 'key', True)
        pn_relay._apns = mock_apns

        notifications = mock_pn_store.get_push_notifications()
        send(pn_provider=pn_provider, device_store=mock_device_store, pn_relay=pn_relay)
        mock_apns.feedback_server.items.assert_called_with()
        expected_mock_apns_calls = [
            mock.call(token_hex=notifications[0].token,
                      payload=notifications[0].payload,
                      identifier=0,
                      expiry=notifications[0].expiry),
            mock.call(token_hex=notifications[1].token,
                      payload=notifications[1].payload,
                      identifier=1,
                      expiry=notifications[1].expiry)]
        self.assertEqual(mock_apns.gateway_server.send_notification.call_args_list,
                         expected_mock_apns_calls)
        self.assertEqual(mock_pn_store.deleted_notifications, [notifications[0], notifications[1]])
        self.assertFalse(mock_device_store.delete_devices_with_tokens.called)


    def test_send_invalid_tokens_from_feedback(self):
        mock_pn_store = self.MockPushNotificationStore()
        pn_provider = SpecificPushNotificationsProvider(PushNotificationsProvider(mock_pn_store),
                                                        app_bundle_id=APP_BUNDLE_ID1,
                                                        for_sandbox=True)
        mock_device_store = mock.Mock()
        mock_device_store.__class__ = AbstractDeviceStore
        mock_device_store.delete_devices_with_tokens.return_value = None

        notifications = mock_pn_store.get_push_notifications()
        invalid_token = notifications[1].token

        mock_apns = mock.Mock()
        mock_apns.feedback_server = mock.Mock()
        mock_apns.feedback_server.items.return_value = [(invalid_token, None)]
        mock_apns.gateway_server = mock.Mock()
        pn_relay = PushNotificationRelay('cert', 'key', True)
        pn_relay._apns = mock_apns

        send(pn_provider=pn_provider, device_store=mock_device_store, pn_relay=pn_relay)
        mock_apns.feedback_server.items.assert_called_with()
        expected_mock_apns_calls = [
            mock.call(token_hex=notifications[0].token,
                      payload=notifications[0].payload,
                      identifier=0,
                      expiry=notifications[0].expiry)]
        self.assertEqual(mock_apns.gateway_server.send_notification.call_args_list,
                         expected_mock_apns_calls)
        self.assertEqual(mock_pn_store.deleted_notifications, [notifications[1], notifications[0]])
        mock_device_store.delete_devices_with_tokens.assert_called_with([invalid_token])


    def test_send_invalid_tokens_from_exception(self):
        mock_pn_store = self.MockPushNotificationStore()
        pn_provider = SpecificPushNotificationsProvider(PushNotificationsProvider(mock_pn_store),
                                                        app_bundle_id=APP_BUNDLE_ID1,
                                                        for_sandbox=True)
        mock_device_store = mock.Mock()
        mock_device_store.__class__ = AbstractDeviceStore
        mock_device_store.delete_devices_with_tokens.return_value = None

        notifications = mock_pn_store.get_push_notifications()
        invalid_token = notifications[1].token

        mock_apns = mock.Mock()
        mock_apns.feedback_server = mock.Mock()
        mock_apns.feedback_server.items.return_value = []
        mock_apns.gateway_server = mock.Mock()
        pn_relay = PushNotificationRelay('cert', 'key', True)
        pn_relay._apns = mock_apns

        def mock_send_with_exception(token_hex, payload, identifier, expiry):
            if identifier == 1:
                self.assertEqual(payload, notifications[1].payload)
                self.assertEqual(token_hex, notifications[1].token)
                raise InvalidTokenError(0)
            else:
                self.assertEqual(payload, notifications[0].payload)
                self.assertEqual(token_hex, notifications[0].token)

        mock_apns.gateway_server.send_notification = mock_send_with_exception
        send(pn_provider=pn_provider, device_store=mock_device_store, pn_relay=pn_relay)
        mock_apns.feedback_server.items.assert_called_with()
        self.assertEqual(mock_pn_store.deleted_notifications, [notifications[0], notifications[1]])
        mock_device_store.delete_devices_with_tokens.assert_called_with([invalid_token])


    def test_send_shutdown_launched(self):
        mock_pn_store = self.MockPushNotificationStore()
        pn_provider = SpecificPushNotificationsProvider(PushNotificationsProvider(mock_pn_store),
                                                        app_bundle_id=APP_BUNDLE_ID1,
                                                        for_sandbox=True)
        mock_device_store = mock.Mock()
        mock_device_store.__class__ = AbstractDeviceStore

        mock_apns = mock.Mock()
        mock_apns.feedback_server = mock.Mock()
        mock_apns.feedback_server.items.return_value = []
        mock_apns.gateway_server = mock.Mock()
        pn_relay = PushNotificationRelay('cert', 'key', True)
        pn_relay._apns = mock_apns

        notifications = mock_pn_store.get_push_notifications()

        def mock_send_with_exception(token_hex, payload, identifier, expiry):
            if identifier == 1:
                self.assertEqual(payload, notifications[1].payload)
                self.assertEqual(token_hex, notifications[1].token)
                raise ShutdownError(0)
            else:
                self.assertEqual(payload, notifications[0].payload)
                self.assertEqual(token_hex, notifications[0].token)

        mock_apns.gateway_server.send_notification = mock_send_with_exception
        send(pn_provider=pn_provider, device_store=mock_device_store, pn_relay=pn_relay)
        mock_apns.feedback_server.items.assert_called_with()
        self.assertEqual(mock_pn_store.deleted_notifications, [notifications[0]])
        self.assertIn(notifications[1], mock_pn_store.get_push_notifications())
        self.assertFalse(mock_device_store.delete_devices_with_tokens.called)


    def test_pn_provider(self):
        mock_pn_store = self.MockPushNotificationStore()
        pn_provider = PushNotificationsProvider(mock_pn_store)
        self.assertEqual(pn_provider.get_app_bundle_ids(), [APP_BUNDLE_ID2, APP_BUNDLE_ID1])

if __name__ == '__main__':
    unittest.main()
