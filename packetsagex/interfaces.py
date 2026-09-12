from __future__ import annotations


def select_live_interface(requested: str, available: list[str], default: str | None) -> str:
    """Resolve PacketSageX's friendly 'any/auto' alias to a real Scapy interface."""
    requested = requested.strip()
    if requested.lower() not in {"any", "auto"}:
        return requested

    if default and default in available and default != "lo":
        return default

    for name in available:
        if name != "lo":
            return name

    if default and default in available:
        return default
    if available:
        return available[0]

    raise RuntimeError("No capture interfaces were found by Scapy.")


def resolve_live_interface(requested: str) -> str:
    if requested.strip().lower() not in {"any", "auto"}:
        return requested.strip()

    try:
        from scapy.all import conf, get_if_list
    except Exception as exc:  # pragma: no cover - dependency/environment specific
        raise RuntimeError("Live capture requires Scapy.") from exc

    available = list(get_if_list())
    default_obj = getattr(conf, "iface", None)
    default = getattr(default_obj, "name", None) or (str(default_obj) if default_obj else None)
    return select_live_interface(requested, available, default)
