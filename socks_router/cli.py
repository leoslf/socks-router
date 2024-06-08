import os
import logging
import logging.config

import pathlib

import click

from typing import Optional

from click_option_group import optgroup, MutuallyExclusiveOptionGroup

from pyaml_env import parse_config


from socks_router.parsers import routing_table
from socks_router.models import ApplicationContext
from socks_router.router import SocksRouter, SocksRouterRequestHandler

logger = logging.getLogger(__name__)


@click.command()
@click.option(
    "--logging-config",
    envvar="LOGGING_CONFIG",
    type=click.Path(dir_okay=False, resolve_path=True),
    default="logging.yaml",
    show_default=True,
)
@click.option("--hostname", envvar="HOSTNAME", default="0.0.0.0", show_default=True)
@click.option(
    "--port",
    envvar="PORT",
    type=click.IntRange(0, 65535),
    default=1080,
    show_default=True,
)
@optgroup.group("Socks Router Routes", cls=MutuallyExclusiveOptionGroup)
@optgroup.option("--routes", envvar="SOCKS_ROUTER_ROUTES", type=str, default=None)
@optgroup.option(
    "--routes-file",
    envvar="SOCKS_ROUTER_ROUTES_FILE",
    type=click.Path(dir_okay=False, resolve_path=True, path_type=pathlib.Path),
    default=os.path.expanduser("~/.ssh/routes"),
    show_default=True,
)
@click.version_option()
@click.pass_context
def cli(
    ctx: click.Context,
    logging_config: str,
    hostname: str,
    port: int,
    routes: Optional[str],
    routes_file: pathlib.Path,
):
    # load logging config
    if os.path.exists(logging_config):
        logging.config.dictConfig(parse_config(logging_config))

    if routes is None and routes_file.exists():
        routes = routes_file.read_text()

    with SocksRouter(
        (hostname, port),
        SocksRouterRequestHandler,
        context=ApplicationContext(
            routing_table=routing_table.parse(routes or ""),
        ),
    ) as server:
        server.serve_forever()
