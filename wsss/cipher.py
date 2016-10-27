#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Cipher
"""
__author__ = 'Zagfai'
__date__   = '2016-08'

import hashlib
import M2Crypto.EVP
import M2Crypto.Rand


ciphers = {
    'aes-128-cfb': (16, 16),
    'aes-256-cfb': (32, 16),
    'camellia-256-cfb': (32, 16),
}

def random_string(length):
    return M2Crypto.Rand.rand_bytes(length)

def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

def EVP_BytesToKey(password, key_len, iv_len, _CACHED={}):
    cached_key = '%s-%d-%d' % (password, key_len, iv_len)
    if cached_key in _CACHED:
        return _CACHED.get(cached_key)
    m = []
    i = 0
    while len(b''.join(m)) < (key_len + iv_len):
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = b''.join(m)
    key = ms[:key_len]
    _CACHED[cached_key] = key
    return key



class Cipher(object):

    def __init__(self, key, iv=None, method=None):
        self.key = key
        self.method = method and method or 'aes-256-cfb'
        self.iv = iv and iv or random_string(ciphers[self.method][1])
        self.enc_cipher = None
        self.dec_cipher = None

    def get_cipher(self, op):
        password = self.key.encode('utf-8')
        method = self.method
        m = ciphers[self.method]
        key = EVP_BytesToKey(password, m[0], m[1])
        return M2Crypto.EVP.Cipher(
                method.replace('-', '_'),
                key, self.iv, op)

    def encrypt(self, buf):
        if not self.enc_cipher:
            self.enc_cipher = self.get_cipher(1)
        if len(buf) == 0:
            return buf
        return self.enc_cipher.update(buf)

    def decrypt(self, buf):
        if not self.dec_cipher:
            self.dec_cipher = self.get_cipher(0)
        if len(buf) == 0:
            return buf
        return self.dec_cipher.update(buf)

def test():
    c = Cipher('12312df32243')
    en = c.encrypt("32131你hou")
    print en, type(en)
    print c.decrypt(en)
    en = c.encrypt("32131你hou")
    print en, type(en)
    print c.decrypt(en)


if __name__ == '__main__':
    test()

