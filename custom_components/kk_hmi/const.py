"""Constants for the KK HMI integration."""
DOMAIN = "kk_hmi"
EVENT = "kk_hmi_event"                  # fired on the HA bus for every HMI `event` frame
CONF_HOST = "host"
CONF_PORT = "port"
CONF_CERT = "client_cert"                # PEM text: the integration's own identity, kept in the entry
CONF_KEY = "client_key"                  # PEM text (private key)
CONF_PIN = "fingerprint"
CONF_DEVICE_ID = "device_id"
DEFAULT_PORT = 443
CLIENT_LABEL = "home-assistant"      # what the admin's app shows in the access list
