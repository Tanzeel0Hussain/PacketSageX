# Authorized Decryption

PacketSageX does **not** break TLS, WhatsApp encryption, or other modern cryptography.

For traffic you own or are explicitly authorized to inspect, PacketSageX can pass an NSS-compatible TLS key log to TShark:

```bash
packetsagex analyze capture.pcapng --tls-keylog sslkeys.log --html report.html
```

A typical browser test lab can create a key log by setting `SSLKEYLOGFILE` before launching the browser, then capturing your own traffic. Whether a session can be decrypted depends on the application/protocol and whether usable session secrets were logged.

Never collect or use another person's secrets without authorization.
