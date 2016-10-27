#!/usr/bin/python
# -*- coding: utf-8 -*-
""" TCP server.
"""
__author__ = 'Zagfai'
__date__   = '2016-08'

import time
import logging
import socket
import struct
from functools import partial
import tornado.gen
import tornado.ioloop
import tornado.iostream
import tornado.tcpserver
import tornado.tcpclient
#from webtul import cipher
from . import cipher
#from . import user


class Server(tornado.tcpserver.TCPServer):
    client = tornado.tcpclient.TCPClient()
    pwd = ""
    #user_manager = user.UserManager()

    @tornado.gen.coroutine
    def handle_stream(self, stream, address):
        t0 = time.time()
        stream.user_addr = address
        stream.suuid = str(int(time.time()*1000))[-6:]
        user_stream = stream
        logging.info("Connected from %s %s" % address)

        # iv and uid
        iv = yield user_stream.read_bytes(16)
        user_stream.iv = iv
        user_stream.user = "No user version"
        user_stream.set_nodelay(True)

        # payload
        encryptor = cipher.Cipher(self.pwd)
        decryptor = cipher.Cipher(self.pwd, iv)
        down_iv = encryptor.iv

        analyzed_addr = yield self.analyze_encrypted_header(
                user_stream, decryptor.decrypt)
        if not analyzed_addr:
            stream.close()
            raise tornado.gen.Return()
        logging.debug("TimeDelta T1: %s %s" % (
                time.time()-t0, user_stream.suuid))

        # communicating
        try:
            web_stream = yield self.client.connect(*analyzed_addr)
        except socket.gaierror:
            logging.info("Domain resolve %s error." % analyzed_addr[0])
            web_stream = None
        except tornado.iostream.StreamClosedError:
            web_stream = None
        if not web_stream:
            stream.close()
            raise tornado.gen.Return()
        web_stream.set_nodelay(True)
        logging.debug("TimeDelta T2: %s %s" % (
                time.time()-t0, user_stream.suuid))

        yield user_stream.write(down_iv)
        user_stream.set_close_callback(partial(self.do_close, 'uf',web_stream))
        web_stream.set_close_callback(partial(self.do_close, 'df',user_stream))
        user_stream.read_until_close(
            streaming_callback=partial(self.write_stream,
                user_stream, web_stream, decryptor.decrypt, 'upflow'
        ))
        web_stream.read_until_close(
            streaming_callback=partial(self.write_stream,
                web_stream, user_stream, encryptor.encrypt, 'downflow'
        ))


    @tornado.gen.coroutine
    def analyze_encrypted_header(self, user_stream, decrypt):
        datype = yield user_stream.read_bytes(1)
        datype = decrypt(datype)
        atype, = struct.unpack("!B", datype)

        if atype == 0x01:
            daddr = yield user_stream.read_bytes(4)
            daddr = decrypt(daddr)
            addr = socket.inet_ntop(socket.AF_INET, daddr)
        elif atype == 0x03:
            ddsize = yield user_stream.read_bytes(1)
            ddsize = decrypt(ddsize)
            domain_size, = struct.unpack("!B", ddsize)
            daddr = yield user_stream.read_bytes(domain_size)
            addr = decrypt(daddr)
        else:
            logging.error("Atype error, from %s " % user_stream.user)
            raise tornado.gen.Return()

        dport = yield user_stream.read_bytes(2)
        dport = decrypt(dport)
        port, = struct.unpack("!H", dport)

        # HMAC-SIGN-CHECK
        #dsign = yield user_stream.read_bytes(10)
        #sign_str = '\n'.join([user_stream.iv, str(atype), addr, str(port)])
        #if dsign != hashlib.sha1(sign_str).digest()[:10]:
        #    logging.error("Signature error, from %s " % user_stream.user)
        #    raise tornado.gen.Return()

        logging.info("Connect %s:%s from %s in %s" % (
            addr, port, user_stream.user, user_stream.suuid))
        raise tornado.gen.Return((addr, port))


    def write_stream(self, from_stream, to_stream, crypt, flow, data):
        if data:
            #logging.debug("Transfer %s %s bytes." % (flow, len(data)))
            try:
                to_stream.write(crypt(data))
            except tornado.iostream.StreamClosedError:
                from_stream.close()


    def do_close(self, by, stream):
        if not stream.closed():
            try:
                stream.close()
                logging.debug("Done close by %s" % by)
            except tornado.iostream.StreamClosedError:
                pass

