from __future__ import annotations

BANNER = r"""
████    ███    ████  █   █  █████  █████   ████   ███    ████  █████  █   █
█   █  █   █  █      █  █   █        █    █      █   █  █      █       █ █
████   █████  █      ███    ████     █     ███   █████  █  ██  ████     █
█      █   █  █      █  █   █        █        █  █   █  █   █  █       █ █
█      █   █   ████  █   █  █████    █    ████   █   █   ████  █████  █   █
""".strip("\n")

TAGLINE = "Network Traffic Intelligence & Forensics Platform"


def render_banner(version: str, *, color: bool = True) -> str:
    """Render the terminal brand with a cyber-console look.

    ANSI color is optional so redirected output and NO_COLOR environments stay clean.
    """
    status = f"[ PACKETSAGEX://FORENSICS ]  [ CORE v{version} ]  [ STATUS: ONLINE ]"
    subtitle = ":: packet intelligence  //  flow analytics  //  defensive forensics ::"
    if not color:
        return f"{BANNER}\n{status}\n{subtitle}\n{TAGLINE}"

    cyan = "\033[96m"
    green = "\033[92m"
    dim = "\033[2m"
    reset = "\033[0m"
    return (
        f"{cyan}{BANNER}{reset}\n"
        f"{green}{status}{reset}\n"
        f"{dim}{subtitle}{reset}\n"
        f"{TAGLINE}"
    )
