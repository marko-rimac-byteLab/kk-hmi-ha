# KK HMI for Home Assistant

A read-only Home Assistant integration for the KK solar storage HMI. It connects to the HMI's local
channel (a WebSocket over mutual TLS on your own network), receives telemetry as it is pushed, and
turns it into sensors. It never sends a command: Home Assistant is enrolled as a **viewer**.

No cloud account and no extra Python packages are needed.

## Install (HACS)

1. In Home Assistant open HACS, then the three-dot menu, then **Custom repositories**.
2. Add `https://github.com/marko-rimac-byteLab/kk-hmi-ha` with type **Integration**.
3. Install **KK HMI** and restart Home Assistant.

Manual install: copy `custom_components/kk_hmi` into your Home Assistant `config/custom_components/`
folder and restart.

Requires Home Assistant 2024.11 or newer.

## Set up

You need the KK app (or any admin client) on the same network as Home Assistant, and the HMI
provisioned and online.

1. **Discovery.** Home Assistant finds the HMI by itself (`_kkstorage._tcp`) and offers it under
   *Settings > Devices & services*. If it does not, choose **Add integration > KK HMI** and type the
   HMI's IP address (port 443).
2. **In the app,** open the HMI and tap **Add local client**. Choose role **viewer** and label
   `home-assistant`. The app shows a code like `ABCD-2345`. It is valid for two minutes and works once.
3. **In Home Assistant,** type the code into the form and submit.

Behind the scenes Home Assistant creates its own key and certificate (they never leave your Home
Assistant), enrols them with the HMI using the code, remembers the HMI's server key, and then proves it
works by connecting. The certificate, key and server key are stored in the integration's config entry.
There are no files to copy.

## What you get

One device per HMI with these entities (battery packs and cells appear as the HMI reports them):

- **Power**: PV channels, AC output (power, voltage, frequency), grid import and export, battery power,
  house load
- **Battery**: per pack state of charge, voltage, current, state of health, temperature, cell voltages
  (min, max, delta)
- **Temperatures**: inverter heat sink, enclosure, ambient
- **Generator**: state, relay, voltage, frequency, runtime
- **Mode**: operating mode, power level, grid present, backup active, backup outlet armed
- **Alarms**: number of active alarms and their list, link to the power controller

Every HMI event (alarm raised or cleared, relay changes, backup transitions) is also fired on the Home
Assistant bus as `kk_hmi_event` with the fields `device_id`, `name`, `data` and `ts`, so automations
can trigger on them.

The integration is a viewer on purpose: it has no switches, numbers or services that change the HMI.

## Reauthenticate

If the HMI revokes this client (an admin removed it) or its server key changes (factory reset), the
integration stops and Home Assistant shows **Reauthenticate**. Tap **Add local client** in the app again,
then type the new code. Entity history is kept.

## Troubleshooting

| You see | Meaning and fix |
| --- | --- |
| *No enrolment window is open* | The code expired (two minutes), was already used, or five wrong codes locked the window. Tap **Add local client** again. |
| *The code is wrong* | Check the characters (no 0, 1, I, O). Five wrong codes lock the window. |
| *Cannot reach the HMI* | Check the address and that Home Assistant and the HMI are on the same network. The enrolment uses port 8443 and the data channel port 443. |
| *The HMI already has 4 local clients* | The HMI allows four local clients at once. Disconnect another (for example a phone app), then add a new code. A Repairs entry appears while Home Assistant cannot get in and clears itself afterwards. |
| *Different device* during reauthentication | The code belongs to another HMI than the one configured. |
| Entities flicker unavailable | Enable debug logging for `custom_components.kk_hmi`. A close with code 4408 is logged as a warning (idle timeout). |

Logging:

```yaml
logger:
  logs:
    custom_components.kk_hmi: debug
```

## Security notes

- The data channel is mutual TLS. Home Assistant pins the HMI's server key (SHA-256 of its public key)
  that it received during enrolment, so a different device on the same address is refused.
- The enrolment code is a short-lived, single-use password for an SRP6a exchange: it is never sent over
  the network.
- To remove access, delete the client in the KK app (the HMI closes its connection within a second) and
  remove the integration in Home Assistant.
