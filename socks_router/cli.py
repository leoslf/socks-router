import os
import logging
import logging.config

import pathlib

import click

from typing import Optional, cast

from click_option_group import optgroup, MutuallyExclusiveOptionGroup

from pyaml_env import parse_config

from socks_router.parsers import routing_table
from socks_router.models import ApplicationContext, RetryOptions, RoutingTable
from socks_router.router import SocksRouter, SocksRouterRequestHandler
from socks_router.proxies import Proxy, observer, create_proxy

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
@click.option("--retries", envvar="SOCKS_ROUTER_RETRIES", type=int, default=-1)
@click.version_option()
@click.pass_context
def cli(
    ctx: click.Context,
    logging_config: str,
    hostname: str,
    port: int,
    routes: Optional[str],
    routes_file: pathlib.Path,
    retries: int,
):
    # load logging config
    if os.path.exists(logging_config):
        logging.config.dictConfig(parse_config(logging_config))

    routing_table_proxy = create_proxy(routes, routes_file, parser=routing_table.parse, default="")
    with observer(cast(Proxy[RoutingTable], routing_table_proxy)):
        with SocksRouter(
            (hostname, port),
            SocksRouterRequestHandler,
            context=ApplicationContext(
                routing_table=routing_table_proxy,
                proxy_retry_options=RetryOptions(tries=retries),
            ),
        ) as server:
            server.serve_forever()
