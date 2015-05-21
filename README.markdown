# A8-PyAPNs 

A Python library for interacting with the Apple Push Notification service 
(APNs)

## Sample usage

```python
from apns import APNs, Payload

apns = APNs(use_sandbox=True, cert_file='cert.pem', key_file='key.pem')

# Send a notification
token_hex = '<here is device token>'
payload = Payload(alert="Hello World!", sound="default", badge=1)
apns.gateway_server.send_notification(token_hex, payload)

