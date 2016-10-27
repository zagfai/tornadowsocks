#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Server.
Start with me.
"""
__author__ = 'Zagfai'
__date__   = '2016-08'

import socket
import logging
import tornado.ioloop
from tornado.netutil import Resolver
Resolver.configure('tornado.netutil.ThreadedResolver', num_threads=15)

from wsss import tcp
from wsss import config


def main():
    cfg = config.get(True)
    server = tcp.Server(max_buffer_size=1024*1024*1024)
    server.pwd = cfg.pwd
    ports = []
    for port in cfg.port:
        try:
            server.listen(port)
            ports.append(port)
        except socket.error:
            logging.warn("port %s fail to listen to" % port)
            if not cfg.debug:
                exit(1)
    logging.info("Started on: %s" % ports)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    import sys
    sys.argv.extend(['-c', 'config.json'])
    main()

