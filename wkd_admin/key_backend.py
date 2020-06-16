# configuration
#import wkd_admin.config
from config import WKD_KEY_STORE, GPG_TEMP
import os
import secrets
import itertools
import functools
import gnupg
from tempfile import mkdtemp
import base64
import shutil
import email
import hashlib
import json





class KeyInspector(object):
    def __init__(self, armored_key, temp_path):
        self.armored_key = armored_key
        self.email = ""
        self.domain = ""
        self.local_part = ""
        self.keyring_path = ""
        self.is_key = None
        self.temp_keyring_path = ""
        self.gpg = None

        # build a temporary place for empty keyring
        self.temp_keyring_path = mkdtemp(prefix=temp_path)

        # Init the GPG
        self.gpg = gnupg.GPG(gnupghome=self.temp_keyring_path, options=[
            '--with-colons',
            '--keyid-format=LONG',
            '--export-options=export-minimal,export-clean,no-export-attributes',
            '--import-options=import-minimal,import-clean'
        ], verbose=False)

        # Blindly try to import and check result. If we have count we are fine
        import_result = self.gpg.import_keys(self.armored_key)
        if import_result.count <= 0:
            self.is_key = False
        else:
            self.is_key = True

    def __del__(self):
        shutil.rmtree(self.temp_keyring_path)

    def is_openpgp_key(self):
        return self.is_key

    def is_valid_domain(self, domain_list):
        self.get_address_info()
        is_key_valid_domain = False
        for domain in domain_list:
            if domain == self.domain:
                is_key_valid_domain = True
                break
        return is_key_valid_domain

    def get_address_info(self):
        imported_keys = self.gpg.list_keys()
        is_key_valid_domain = False
        for key in imported_keys:
            for uid in key.get('uids', []):
                address = email.utils.parseaddr(uid)[1]
            if '@' not in address:
                continue
            self.email = address.lower()
            self.local_part, self.domain = self.email.split("@", 1)

        return self.email, self.local_part, self.domain

    def get_fingerprint(self):
        imported_keys = self.gpg.list_keys()
        for key in imported_keys:
            for uid in key.get('uids', []):
                address = email.utils.parseaddr(uid)[1]
                if '@' not in address:
                    continue
            return key["fingerprint"]
        return None


class HKPTools:
    # Source: https://gist.githubusercontent.com/tochev/99f19d9ce062f1c7e203
    # /raw/0077ec38adc350e0fd1207e6a525de482b40df7e/zbase32.py
    # Copyright: Tocho Tochev <tocho AT tochev DOT net>
    # Licence: MIT
    # See http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
    @staticmethod
    def zb32_encode(bs):
        """
        Encode bytes bs using zbase32 encoding.
        Returns: bytearray

        >>> encode_zbase32(b'\\xd4z\\x04') == b'4t7ye'
        True
        """
        ALPTHABET = b"ybndrfg8ejkmcpqxot1uwisza345h769"
        result = bytearray()
        for word in itertools.zip_longest(*([iter(bs)] * 5)):
            padding_count = word.count(None)
            n = functools.reduce(lambda x, y: (x << 8) + (y or 0), word, 0)
            for i in range(0, (40 - 8 * padding_count), 5):
                result.append(ALPTHABET[(n >> (35 - i)) & 0x1F])
        return result

    # source: https://gitlab.com/Martin_/generate-openpgpkey-hu-3/blob/master/\
    #         generate-openpgpkey-hu-3
    # generate-openpgpkey-hu-3
    # Copyright 2017, W. Martin Borgert <debacle@debian.org>
    # License: GPL-3+
    def localpart2zbase32(s):
        """transforms local part to lower case, SHA1s it, and encodes zbase32

        See https://tools.ietf.org/id/draft-koch-openpgp-webkey-service-01.html

        >>> localpart2zbase32('Joe.Doe')
        'iy9q119eutrkn8s1mk4r39qejnbu3n5q'
        """
        return HKPTools.zb32_encode(
            hashlib.sha1(s.lower().encode("utf-8")).digest()).decode("utf-8")


# //TODO: class WKDFilestore(add, update, delete, does key for email exist, list)
class WKDFileStore(object):
    def __init__(self, path):
        self.path = str(WKD_KEY_STORE)

    def add(self, email, armored_key):
        # check key and email
        _inspector = KeyInspector(armored_key, GPG_TEMP)

        if _inspector.is_key is False:
            raise ValueError

        _email, _localpart, _domain = _inspector.get_address_info()
        if _email.lower() != email.lower():
            raise ValueError

        self.delete(email)

        zb32filename = HKPTools.localpart2zbase32(_localpart)
        with open(os.path.join(self.path, _domain, zb32filename), "wb+") as f:
                _key = _inspector.gpg.export_keys(email.lower(), armor=False)
                f.write(_key)

    def delete(self, iemail):
        # get localpart of email
        address = email.utils.parseaddr(iemail)[1]
        if '@' not in address:
            return False
        address = address.lower()
        # check if file exists & delete it
        local_part, domain = address.split("@", 1)
        zb32local = HKPTools.localpart2zbase32(local_part)
        key_path = os.path.join(self.path, domain, zb32local)
        if os.path.isfile(key_path) and os.access(key_path, os.R_OK):
            os.remove(key_path)
            return True
        return False

    def is_key_available(self, iemail):
        # check if key for email exists
        address = email.utils.parseaddr(iemail)[1]
        if '@' not in address:
            return False
        address = address.lower()
        local_part, domain = iemail.split("@", 1)
        zb32local = HKPTools.localpart2zbase32(local_part)
        key_path = os.path.join(self.path, domain, zb32local)
        if os.path.isfile(key_path) and os.access(key_path, os.R_OK):
            return True
        return False

class Utils(object):
    @staticmethod
    def is_email_allowed(email, domain_allow_list):
        _local_part, _domain = email.split("@", 1)
        if _domain not in domain_allow_list:
            return False
        else:
            return True
