import os
import logging

import re

from threading import Lock
from functools import partial, partialmethod

from socketserver import ThreadingTCPServer

from socks_router.router import SocksRouter, read_routing_table

if __name__ == "__main__":
    # custom logging level
    logging.TRACE = 5
    logging.addLevelName(logging.TRACE, 'TRACE')
    logging.Logger.trace = partialmethod(logging.Logger.log, logging.TRACE)
    logging.trace = partial(logging.log, logging.TRACE)

    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper())

    routing_table = read_routing_table()

    mutex = Lock()
    ssh_clients = {}
    upstreams = {}

    with ThreadingTCPServer(("0.0.0.0", 1080), lambda *argv, **kwargs: SocksRouter(routing_table, mutex, ssh_clients, upstreams, *argv, **kwargs)) as server:
        server.serve_forever()
