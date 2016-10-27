#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Config reader.
"""
__author__ = 'Zagfai'
__date__   = '2016-08'

import os
import json
import logging
import argparse

from .lib import structify

LOGGING_FORMAT = '[%(levelname)1.1s %(asctime)s %(filename)s:%(lineno)d] %(message)s'
DATE_FORMAT = '%y%m%d %H:%M:%S'

def get(debug=False):
    log_level = debug and logging.DEBUG or logging.INFO
    logging.basicConfig(
            format = LOGGING_FORMAT,
            level = log_level,
            datefmt=DATE_FORMAT)
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help='Configure path.')
    args, unknown = parser.parse_known_args()

    if not args.config:
        logging.error("No config error.")
        raise Exception("No config error.")

    path = os.path.join(os.getcwd(), args.config)
    cfgf = open(path, 'r').read()
    cfg = json.loads(cfgf)

    return structify.Struct(cfg)

