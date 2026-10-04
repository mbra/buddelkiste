"""Entry point run inside a private netns to install filter rules and exec bwrap."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click

from buddelkiste.network import NetworkConfig, run_network_inner


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    start_slirp = False
    if "--start-slirp" in argv:
        argv.remove("--start-slirp")
        start_slirp = True

    if len(argv) != 2:
        raise SystemExit("usage: python -m buddelkiste.network_inner NET.json BWRAP.json [--start-slirp]")

    logging.basicConfig(level=logging.WARNING)

    net_data = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    bwrap_args = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    net = NetworkConfig(
        mode=net_data["mode"],
        policy=net_data["policy"],
        allow=list(net_data.get("allow", [])),
        deny=list(net_data.get("deny", [])),
    )
    try:
        run_network_inner(net, bwrap_args, start_slirp=start_slirp)
    except click.ClickException as exc:
        click.echo(f"Error: {exc.format_message()}", err=True)
        raise SystemExit(1) from exc
    raise SystemExit("network_inner: exec failed")


if __name__ == "__main__":
    main()
