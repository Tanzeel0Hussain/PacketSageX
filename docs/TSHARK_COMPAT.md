# TShark path-permission compatibility

PacketSageX normally asks TShark to read the original capture path directly. Some Linux security profiles can allow the same capture to be read from `/tmp` while denying TShark direct access to another user-readable path.

PacketSageX v0.4.1 handles this without disabling AppArmor or other host security controls. If the direct TShark read fails specifically with a permission-denied error, PacketSageX creates a private temporary directory, copies the capture there with `0600` permissions, also stages an optional TLS key log with `0600` permissions, retries TShark, and removes the temporary directory automatically after analysis.

This behavior is only a compatibility retry. It does not bypass capture permissions: the PacketSageX process must itself be able to read the original capture and any key log supplied by the user.
