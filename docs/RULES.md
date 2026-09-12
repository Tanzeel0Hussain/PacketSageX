# Traffic Signature Rules

Built-in application hints live in `packetsagex/intelligence/signatures.json`.

Each rule can use:

- `name`: human-readable classification
- `domains`: DNS/SNI/HTTP host substrings
- `ports`: common service ports
- `protocols`: dissector protocol names
- `min_packets`: optional weak flow-volume signal

The engine combines matching signals into a confidence score. Domain evidence is weighted more strongly than a port because port 443 is shared by many applications.

When adding a rule, prefer stable vendor-owned domains and well-documented service ports. Avoid claiming certainty from weak metadata alone.
