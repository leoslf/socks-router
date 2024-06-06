import os
import logging
import logging.config

import pathlib

import click

from typing import Optional, cast

from click_option_group import optgroup, MutuallyExclusiveOptionGroup

from pyaml_env import parse_config

from threading import Lock

from socks_router.parsers import configuration
from socks_router.models import ApplicationContext, RoutingTable
from socks_router.router import SocksRouter, SocksRouterRequestHandler

logger = logging.getLogger(__name__)

@click.command()
@click.option("--logging-config", envvar="LOGGING_CONFIG", type=click.Path(exists=True, dir_okay=False, resolve_path=True), default="logging.yaml", show_default=True)
@click.option("--hostname", envvar="HOSTNAME", default="0.0.0.0", show_default=True)
@click.option("--port", envvar="PORT", type=click.IntRange(0, 65535), default=1080, show_default=True)
@optgroup.group("Socks Router Routes", cls=MutuallyExclusiveOptionGroup)
@optgroup.option("--routes", envvar="SOCKS_ROUTER_ROUTES", type=str, default=None)
@optgroup.option("--routes-file", envvar="SOCKS_ROUTER_ROUTES_FILE", type=click.Path(exists=True, dir_okay=False, resolve_path=True, path_type=pathlib.Path), default=os.path.expanduser("~/.ssh/routes"), show_default=True)
@click.version_option()
@click.pass_context
def cli(ctx: click.Context,
        logging_config: str,
        hostname: str,
        port: int,
        routes: Optional[str],
        routes_file: Optional[pathlib.Path]):
    # load logging config
    logging.config.dictConfig(
        parse_config(logging_config)
    )

    routing_table: RoutingTable = configuration.parse(routes or cast(pathlib.Path, routes_file).read_text())
    context = ApplicationContext(hostname, port, routing_table, Lock(), {})

    with SocksRouter(context, (hostname, port), SocksRouterRequestHandler) as server:
        server.serve_forever()

