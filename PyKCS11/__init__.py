"""
  Copyright (C) 2006-2025 Ludovic Rousseau (ludovic.rousseau@free.fr)
  Copyright (C) 2010 Giuseppe Amato (additions to original interface)

This file is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
"""

# pylint: disable=too-many-lines

import os
import sys
import threading

import PyKCS11.LowLevel

from .constants import *

# special CKR[] values
CKR[-4] = "C_GetFunctionList() not found"
CKR[-3] = "Unknown format"
CKR[-2] = "Unkown PKCS#11 type"
CKR[-1] = "Load"


class ckbytelist(PyKCS11.LowLevel.ckbytelist):
    """
    add a __repr__() method to the LowLevel equivalent
    """

    def __init__(self, data=None):
        if data is None:
            data = 0
        elif isinstance(data, str):
            data = data.encode("utf-8")
        elif isinstance(data, (bytes, list, ckbytelist)):
            data = bytes(data)
        else:
            raise PyKCS11.PyKCS11Error(-3, text=str(type(data)))
        super().__init__(data)

    def __repr__(self):
        """
        return the representation of a tuple
        the __str__ method will use it also
        """
        rep = [int(elt) for elt in self]
        return repr(rep)

    def __add__(self, b):
        return ckbytelist(bytes(self) + bytes(b))


class CK_OBJECT_HANDLE(PyKCS11.LowLevel.CK_OBJECT_HANDLE):
    """
    add a __repr__() method to the LowLevel equivalent
    """

    def __init__(self, session):
        PyKCS11.LowLevel.CK_OBJECT_HANDLE.__init__(self)
        self.session = session

    def to_dict(self):
        """
        convert the fields of the object into a dictionnary
        """
        # all the attibutes defined by PKCS#11
        all_attributes = PyKCS11.CKA.keys()

        # only use the integer values and not the strings like 'CKM_RSA_PKCS'
        all_attributes = [attr for attr in all_attributes if isinstance(attr, int)]

        # all the attributes of the object
        attributes = self.session.getAttributeValue(self, all_attributes)

        dico = {}
        for key, attr in zip(all_attributes, attributes):
            if attr is None:
                continue
            if key == CKA_CLASS:
                dico[PyKCS11.CKA[key]] = PyKCS11.CKO[attr]
            elif key == CKA_CERTIFICATE_TYPE:
                dico[PyKCS11.CKA[key]] = PyKCS11.CKC[attr]
            elif key == CKA_KEY_TYPE:
                dico[PyKCS11.CKA[key]] = PyKCS11.CKK[attr]
            else:
                dico[PyKCS11.CKA[key]] = attr
        return dico

    def __repr__(self):
        """
        text representation of the object
        """
        dico = self.to_dict()
        lines = []
        for key in sorted(dico.keys()):
            lines.append(f"{key}: {dico[key]}")
        return "\n".join(lines)


class CkClass:
    """
    Base class for CK_* classes
    """

    # dictionnary of integer_value: text_value for the flags bits
    flags_dict = {}

    # dictionnary of fields names and types
    # type can be "pair", "flags" or "text"
    fields = {}

    flags = 0

    def flags2text(self):
        """
        parse the `self.flags` field and create a list of `CKF_*` strings
        corresponding to bits set in flags

        :return: a list of strings
        :rtype: list
        """
        r = []
        for k, v in self.flags_dict.items():
            if self.flags & k:
                r.append(v)
        return r

    def state2text(self):
        """
        Dummy method. Will be overwriden if necessary
        """
        return ""

    def to_dict(self):
        """
        convert the fields of the object into a dictionnary
        """
        dico = {}
        for field in self.fields:
            if field == "flags":
                dico[field] = self.flags2text()
            elif field == "state":
                dico[field] = self.state2text()
            else:
                dico[field] = self.__dict__[field]
        return dico

    def __str__(self):
        """
        text representation of the object
        """
        dico = self.to_dict()
        lines = []
        for key in sorted(dico.keys()):
            ck_type = self.fields[key]
            if ck_type == "flags":
                flags = ", ".join(dico[key])
                lines.append(f"{key}: {flags}")
            elif ck_type == "pair":
                p1, p2 = dico[key]
                lines.append(f"{key}: {p1}.{p2}")
            else:
                lines.append(f"{key}: {dico[key]}")
        return "\n".join(lines)


class CK_SLOT_INFO(CkClass):
    """
    matches the PKCS#11 CK_SLOT_INFO structure

    :ivar slotDescription: blank padded
    :type slotDescription: string
    :ivar manufacturerID: blank padded
    :type manufacturerID: string
    :ivar flags: See :func:`CkClass.flags2text`
    :type flags: integer
    :ivar hardwareVersion: 2 elements list
    :type hardwareVersion: list
    :ivar firmwareVersion: 2 elements list
    :type firmwareVersion: list
    """

    flags_dict = {
        CKF_TOKEN_PRESENT: "CKF_TOKEN_PRESENT",
        CKF_REMOVABLE_DEVICE: "CKF_REMOVABLE_DEVICE",
        CKF_HW_SLOT: "CKF_HW_SLOT",
    }

    fields = {
        "slotDescription": "text",
        "manufacturerID": "text",
        "flags": "flags",
        "hardwareVersion": "text",
        "firmwareVersion": "text",
    }

    def __init__(self):
        self.slotDescription = None
        self.manufacturerID = None
        self.flags = None
        self.hardwareVersion = None
        self.firmwareVersion = None


class CK_INFO(CkClass):
    """
    matches the PKCS#11 CK_INFO structure

    :ivar cryptokiVersion: Cryptoki interface version
    :type cryptokiVersion: integer
    :ivar manufacturerID: blank padded
    :type manufacturerID: string
    :ivar flags: must be zero
    :type flags: integer
    :ivar libraryDescription: blank padded
    :type libraryDescription: string
    :var libraryVersion: 2 elements list
    :type libraryVersion: list
    """

    fields = {
        "cryptokiVersion": "pair",
        "manufacturerID": "text",
        "flags": "flags",
        "libraryDescription": "text",
        "libraryVersion": "pair",
    }

    def __init__(self):
        self.cryptokiVersion = None
        self.manufacturerID = None
        self.flags = None
        self.libraryDescription = None
        self.libraryVersion = None


class CK_SESSION_INFO(CkClass):
    """
    matches the PKCS#11 CK_SESSION_INFO structure

    :ivar slotID: ID of the slot that interfaces with the token
    :type slotID: integer
    :ivar state: state of the session
    :type state: integer
    :ivar flags: bit flags that define the type of session
    :type flags: integer
    :ivar ulDeviceError: an error code defined by the cryptographic token
    :type ulDeviceError: integer
    """

    flags_dict = {
        CKF_RW_SESSION: "CKF_RW_SESSION",
        CKF_SERIAL_SESSION: "CKF_SERIAL_SESSION",
    }

    def __init__(self):
        self.slotID = None
        self.state = None
        self.flags = None
        self.ulDeviceError = None

    def state2text(self):
        """
        parse the `self.state` field and return a `CKS_*` string
        corresponding to the state

        :return: a string
        :rtype: string
        """
        return CKS[self.state]

    fields = {
        "slotID": "text",
        "state": "text",
        "flags": "flags",
        "ulDeviceError": "text",
    }


class CK_TOKEN_INFO(CkClass):
    """
    matches the PKCS#11 CK_TOKEN_INFO structure

    :ivar label: blank padded
    :type label: string
    :ivar manufacturerID: blank padded
    :type manufacturerID: string
    :ivar model: string blank padded
    :type model: string
    :ivar serialNumber: string blank padded
    :type serialNumber: string
    :ivar flags:
    :type flags: integer
    :ivar ulMaxSessionCount:
    :type ulMaxSessionCount: integer
    :ivar ulSessionCount:
    :type ulSessionCount: integer
    :ivar ulMaxRwSessionCount:
    :type ulMaxRwSessionCount: integer
    :ivar ulRwSessionCount:
    :type ulRwSessionCount: integer
    :ivar ulMaxPinLen:
    :type ulMaxPinLen: integer
    :ivar ulMinPinLen:
    :type ulMinPinLen: integer
    :ivar ulTotalPublicMemory:
    :type ulTotalPublicMemory: integer
    :ivar ulFreePublicMemory:
    :type ulFreePublicMemory: integer
    :ivar ulTotalPrivateMemory:
    :type ulTotalPrivateMemory: integer
    :ivar ulFreePrivateMemory:
    :type ulFreePrivateMemory: integer
    :ivar hardwareVersion: 2 elements list
    :type hardwareVersion: list
    :ivar firmwareVersion: 2 elements list
    :type firmwareVersion: list
    :ivar utcTime: string
    :type utcTime: string
    """

    # pylint: disable=too-many-instance-attributes

    flags_dict = {
        CKF_RNG: "CKF_RNG",
        CKF_WRITE_PROTECTED: "CKF_WRITE_PROTECTED",
        CKF_LOGIN_REQUIRED: "CKF_LOGIN_REQUIRED",
        CKF_USER_PIN_INITIALIZED: "CKF_USER_PIN_INITIALIZED",
        CKF_RESTORE_KEY_NOT_NEEDED: "CKF_RESTORE_KEY_NOT_NEEDED",
        CKF_CLOCK_ON_TOKEN: "CKF_CLOCK_ON_TOKEN",
        CKF_PROTECTED_AUTHENTICATION_PATH: "CKF_PROTECTED_AUTHENTICATION_PATH",
        CKF_DUAL_CRYPTO_OPERATIONS: "CKF_DUAL_CRYPTO_OPERATIONS",
        CKF_TOKEN_INITIALIZED: "CKF_TOKEN_INITIALIZED",
        CKF_SECONDARY_AUTHENTICATION: "CKF_SECONDARY_AUTHENTICATION",
        CKF_USER_PIN_COUNT_LOW: "CKF_USER_PIN_COUNT_LOW",
        CKF_USER_PIN_FINAL_TRY: "CKF_USER_PIN_FINAL_TRY",
        CKF_USER_PIN_LOCKED: "CKF_USER_PIN_LOCKED",
        CKF_USER_PIN_TO_BE_CHANGED: "CKF_USER_PIN_TO_BE_CHANGED",
        CKF_SO_PIN_COUNT_LOW: "CKF_SO_PIN_COUNT_LOW",
        CKF_SO_PIN_FINAL_TRY: "CKF_SO_PIN_FINAL_TRY",
        CKF_SO_PIN_LOCKED: "CKF_SO_PIN_LOCKED",
        CKF_SO_PIN_TO_BE_CHANGED: "CKF_SO_PIN_TO_BE_CHANGED",
    }

    fields = {
        "label": "text",
        "manufacturerID": "text",
        "model": "text",
        "serialNumber": "text",
        "flags": "flags",
        "ulMaxSessionCount": "text",
        "ulSessionCount": "text",
        "ulMaxRwSessionCount": "text",
        "ulRwSessionCount": "text",
        "ulMaxPinLen": "text",
        "ulMinPinLen": "text",
        "ulTotalPublicMemory": "text",
        "ulFreePublicMemory": "text",
        "ulTotalPrivateMemory": "text",
        "ulFreePrivateMemory": "text",
        "hardwareVersion": "pair",
        "firmwareVersion": "pair",
        "utcTime": "text",
    }

    def __init__(self):
        self.label = None
        self.manufacturerID = None
        self.model = None
        self.serialNumber = None
        self.flags = None
        self.ulMaxSessionCount = None
        self.ulSessionCount = None
        self.ulMaxRwSessionCount = None
        self.ulRwSessionCount = None
        self.ulMaxPinLen = None
        self.ulMinPinLen = None
        self.ulTotalPublicMemory = None
        self.ulFreePublicMemory = None
        self.ulTotalPrivateMemory = None
        self.ulFreePrivateMemory = None
        self.hardwareVersion = None
        self.firmwareVersion = None
        self.utcTime = None


class CK_MECHANISM_INFO(CkClass):
    """
    matches the PKCS#11 CK_MECHANISM_INFO structure

    :ivar ulMinKeySize: minimum size of the key
    :type ulMinKeySize: integer
    :ivar ulMaxKeySize: maximum size of the key
    :type ulMaxKeySize: integer
    :ivar flags: bit flags specifying mechanism capabilities
    :type flags: integer
    """

    flags_dict = {
        CKF_HW: "CKF_HW",
        CKF_ENCRYPT: "CKF_ENCRYPT",
        CKF_DECRYPT: "CKF_DECRYPT",
        CKF_DIGEST: "CKF_DIGEST",
        CKF_SIGN: "CKF_SIGN",
        CKF_SIGN_RECOVER: "CKF_SIGN_RECOVER",
        CKF_VERIFY: "CKF_VERIFY",
        CKF_VERIFY_RECOVER: "CKF_VERIFY_RECOVER",
        CKF_GENERATE: "CKF_GENERATE",
        CKF_GENERATE_KEY_PAIR: "CKF_GENERATE_KEY_PAIR",
        CKF_WRAP: "CKF_WRAP",
        CKF_UNWRAP: "CKF_UNWRAP",
        CKF_DERIVE: "CKF_DERIVE",
        CKF_EXTENSION: "CKF_EXTENSION",
    }

    fields = {"ulMinKeySize": "text", "ulMaxKeySize": "text", "flags": "flags"}

    def __init__(self):
        self.ulMinKeySize = None
        self.ulMaxKeySize = None
        self.flags = None


class PyKCS11Error(Exception):
    """define the possible PyKCS11 exceptions"""

    def __init__(self, value, text=""):
        self.value = value
        self.text = text

    def __str__(self):
        """
        The text representation of a PKCS#11 error is something like:
        "CKR_DEVICE_ERROR (0x00000030)"
        """
        if self.value in CKR:
            if self.value < 0:
                return CKR[self.value] + f" ({self.text})"
            return CKR[self.value] + f" (0x{self.value:08X})"
        if self.value & CKR_VENDOR_DEFINED:
            v = self.value & 0xFFFFFFFF & ~CKR_VENDOR_DEFINED
            return f"Vendor error (0x{v:08X})"
        return f"Unknown error (0x{self.value:08X})"


class PyKCS11Lib:
    """high level PKCS#11 binding"""

    # shared by all instances
    _loaded_libs = {}
    _lock = threading.Lock()

    def __init__(self):
        self.lib = PyKCS11.LowLevel.CPKCS11Lib()
        self.pkcs11dll_filename = None

    def __del__(self):
        # pylint: disable=too-many-boolean-expressions
        if (
            PyKCS11
            and PyKCS11.__name__
            and PyKCS11.LowLevel
            and PyKCS11.LowLevel.__name__
            and PyKCS11.LowLevel._LowLevel
            and PyKCS11.LowLevel._LowLevel.__name__
        ):

            # unload the library
            self.unload()

    def load(self, pkcs11dll_filename=None):
        """
        load a PKCS#11 library

        :type pkcs11dll_filename: string
        :param pkcs11dll_filename: the library name.
          If this parameter is not set then the environment variable
          `PYKCS11LIB` is used instead
        :returns: a :class:`PyKCS11Lib` object
        :raises: :class:`PyKCS11Error` (-1): when the load fails
        """
        if pkcs11dll_filename is None:
            pkcs11dll_filename = os.getenv("PYKCS11LIB")
            if pkcs11dll_filename is None:
                raise PyKCS11Error(
                    -1, "No PKCS11 library specified (set PYKCS11LIB env variable)"
                )

        with PyKCS11Lib._lock:
            if self.pkcs11dll_filename is not None:
                self._unload_locked()  # unload the previous library
                # if the instance was previously initialized,
                # create a new low level library object for it
                self.lib = PyKCS11.LowLevel.CPKCS11Lib()

            # if the lib is already in use: reuse it
            if pkcs11dll_filename in PyKCS11Lib._loaded_libs:
                self.lib.Duplicate(PyKCS11Lib._loaded_libs[pkcs11dll_filename]["ref"])
            else:
                # else load it
                rv = self.lib.Load(pkcs11dll_filename)
                if rv != CKR_OK:
                    raise PyKCS11Error(rv, pkcs11dll_filename)
                PyKCS11Lib._loaded_libs[pkcs11dll_filename] = {
                    "ref": self.lib,
                    "nb_users": 0,
                }

            # remember the lib file name
            self.pkcs11dll_filename = pkcs11dll_filename

            # increase user number
            PyKCS11Lib._loaded_libs[pkcs11dll_filename]["nb_users"] += 1

        return self

    def unload(self):
        """
        unload the current instance of a PKCS#11 library
        """
        with PyKCS11Lib._lock:
            self._unload_locked()

    def _unload_locked(self):
        """
        unload the current instance of a PKCS#11 library
        The lock is already held
        """

        # in case NO library was found and used
        if self.pkcs11dll_filename is None:
            return

        if self.pkcs11dll_filename not in PyKCS11Lib._loaded_libs:
            raise PyKCS11Error(
                -1,
                f"invalid PyKCS11Lib state: {self.pkcs11dll_filename} "
                + f"not in {PyKCS11Lib._loaded_libs}",
            )

        # decrease user number
        PyKCS11Lib._loaded_libs[self.pkcs11dll_filename]["nb_users"] -= 1

        if PyKCS11Lib._loaded_libs[self.pkcs11dll_filename]["nb_users"] == 0:
            # unload only if no more used
            self.lib.Unload()

        # remove unused entry
        # the case < 0 happens if lib loading failed
        if PyKCS11Lib._loaded_libs[self.pkcs11dll_filename]["nb_users"] <= 0:
            del PyKCS11Lib._loaded_libs[self.pkcs11dll_filename]

        self.pkcs11dll_filename = None

    def initToken(self, slot, pin, label):
        """
        C_InitToken

        :param slot: slot number returned by :func:`getSlotList`
        :type slot: integer
        :param pin: Security Officer's initial PIN
        :param label: new label of the token
        """
        pin1 = ckbytelist(pin)
        rv = self.lib.C_InitToken(slot, pin1, label)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def getInfo(self):
        """
        C_GetInfo

        :return: a :class:`CK_INFO` object
        """
        info = PyKCS11.LowLevel.CK_INFO()
        rv = self.lib.C_GetInfo(info)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        i = CK_INFO()
        i.cryptokiVersion = (info.cryptokiVersion.major, info.cryptokiVersion.minor)
        i.manufacturerID = info.GetManufacturerID()
        i.flags = info.flags
        i.libraryDescription = info.GetLibraryDescription()
        i.libraryVersion = (info.libraryVersion.major, info.libraryVersion.minor)
        return i

    def getSlotList(self, tokenPresent=False):
        """
        C_GetSlotList

        :param tokenPresent: `False` (default) to list all slots,
          `True` to list only slots with present tokens
        :type tokenPresent: bool
        :return: a list of available slots
        :rtype: list
        """
        slotList = PyKCS11.LowLevel.ckulonglist()
        rv = self.lib.C_GetSlotList(CK_TRUE if tokenPresent else CK_FALSE, slotList)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        s = []
        for x in slotList:
            s.append(x)
        return s

    def getSlotInfo(self, slot):
        """
        C_GetSlotInfo

        :param slot: slot number returned by :func:`getSlotList`
        :type slot: integer
        :return: a :class:`CK_SLOT_INFO` object
        """
        slotInfo = PyKCS11.LowLevel.CK_SLOT_INFO()
        rv = self.lib.C_GetSlotInfo(slot, slotInfo)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        s = CK_SLOT_INFO()
        s.slotDescription = slotInfo.GetSlotDescription()
        s.manufacturerID = slotInfo.GetManufacturerID()
        s.flags = slotInfo.flags
        s.hardwareVersion = slotInfo.GetHardwareVersion()
        s.firmwareVersion = slotInfo.GetFirmwareVersion()

        return s

    def getTokenInfo(self, slot):
        """
        C_GetTokenInfo

        :param slot: slot number returned by :func:`getSlotList`
        :type slot: integer
        :return: a :class:`CK_TOKEN_INFO` object
        """
        tokeninfo = PyKCS11.LowLevel.CK_TOKEN_INFO()
        rv = self.lib.C_GetTokenInfo(slot, tokeninfo)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        t = CK_TOKEN_INFO()
        t.label = tokeninfo.GetLabel()
        t.manufacturerID = tokeninfo.GetManufacturerID()
        t.model = tokeninfo.GetModel()
        t.serialNumber = tokeninfo.GetSerialNumber()
        t.flags = tokeninfo.flags
        t.ulMaxSessionCount = tokeninfo.ulMaxSessionCount
        if t.ulMaxSessionCount == CK_UNAVAILABLE_INFORMATION:
            t.ulMaxSessionCount = -1
        t.ulSessionCount = tokeninfo.ulSessionCount
        if t.ulSessionCount == CK_UNAVAILABLE_INFORMATION:
            t.ulSessionCount = -1
        t.ulMaxRwSessionCount = tokeninfo.ulMaxRwSessionCount
        if t.ulMaxRwSessionCount == CK_UNAVAILABLE_INFORMATION:
            t.ulMaxRwSessionCount = -1
        t.ulRwSessionCount = tokeninfo.ulRwSessionCount
        if t.ulRwSessionCount == CK_UNAVAILABLE_INFORMATION:
            t.ulRwSessionCount = -1
        t.ulMaxPinLen = tokeninfo.ulMaxPinLen
        t.ulMinPinLen = tokeninfo.ulMinPinLen
        t.ulTotalPublicMemory = tokeninfo.ulTotalPublicMemory

        if t.ulTotalPublicMemory == CK_UNAVAILABLE_INFORMATION:
            t.ulTotalPublicMemory = -1
        t.ulFreePublicMemory = tokeninfo.ulFreePublicMemory
        if t.ulFreePublicMemory == CK_UNAVAILABLE_INFORMATION:
            t.ulFreePublicMemory = -1
        t.ulTotalPrivateMemory = tokeninfo.ulTotalPrivateMemory
        if t.ulTotalPrivateMemory == CK_UNAVAILABLE_INFORMATION:
            t.ulTotalPrivateMemory = -1
        t.ulFreePrivateMemory = tokeninfo.ulFreePrivateMemory
        if t.ulFreePrivateMemory == CK_UNAVAILABLE_INFORMATION:
            t.ulFreePrivateMemory = -1
        t.hardwareVersion = (
            tokeninfo.hardwareVersion.major,
            tokeninfo.hardwareVersion.minor,
        )
        t.firmwareVersion = (
            tokeninfo.firmwareVersion.major,
            tokeninfo.firmwareVersion.minor,
        )
        t.utcTime = tokeninfo.GetUtcTime().replace("\000", " ")

        return t

    def openSession(self, slot, flags=0):
        """
        C_OpenSession

        :param slot: slot number returned by :func:`getSlotList`
        :type slot: integer
        :param flags: 0 (default), `CKF_RW_SESSION` for RW session
        :type flags: integer
        :return: a :class:`Session` object
        """
        se = PyKCS11.LowLevel.CK_SESSION_HANDLE()
        flags |= CKF_SERIAL_SESSION
        rv = self.lib.C_OpenSession(slot, flags, se)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        return Session(self, se)

    def closeAllSessions(self, slot):
        """
        C_CloseAllSessions

        :param slot: slot number
        :type slot: integer
        """
        rv = self.lib.C_CloseAllSessions(slot)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def getMechanismList(self, slot):
        """
        C_GetMechanismList

        :param slot: slot number returned by :func:`getSlotList`
        :type slot: integer
        :return: the list of available mechanisms for a slot
        :rtype: list
        """
        mechanismList = PyKCS11.LowLevel.ckulonglist()
        rv = self.lib.C_GetMechanismList(slot, mechanismList)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        m = []
        for mechanism in mechanismList:
            if mechanism >= CKM_VENDOR_DEFINED:
                mecha = mechanism - CKM_VENDOR_DEFINED
                k = f"CKM_VENDOR_DEFINED_0x{mecha:X}"
                CKM[k] = mechanism
                CKM[mechanism] = k
            m.append(CKM[mechanism])
        return m

    def getMechanismInfo(self, slot, ckm_type):
        """
        C_GetMechanismInfo

        :param slot: slot number returned by :func:`getSlotList`
        :type slot: integer
        :param ckm_type: a `CKM_*` type
        :type ckm_type: integer
        :return: information about a mechanism
        :rtype: a :class:`CK_MECHANISM_INFO` object
        """
        info = PyKCS11.LowLevel.CK_MECHANISM_INFO()
        rv = self.lib.C_GetMechanismInfo(slot, CKM[ckm_type], info)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        i = CK_MECHANISM_INFO()
        i.ulMinKeySize = info.ulMinKeySize
        i.ulMaxKeySize = info.ulMaxKeySize
        i.flags = info.flags

        return i

    def waitForSlotEvent(self, flags=0):
        """
        C_WaitForSlotEvent

        :param flags: 0 (default) or `CKF_DONT_BLOCK`
        :type flags: integer
        :return: slot
        :rtype: integer
        """
        tmp = 0
        (rv, slot) = self.lib.C_WaitForSlotEvent(flags, tmp)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        return slot


class Mechanism:
    """Wraps CK_MECHANISM"""

    # pylint: disable=too-few-public-methods

    def __init__(self, mechanism, param=None):
        """
        :param mechanism: the mechanism to be used
        :type mechanism: integer, any `CKM_*` value
        :param param: data to be used as crypto operation parameter
          (i.e. the IV for some algorithms)
        :type param: string or list/tuple of bytes

        :see: :func:`Session.decrypt`, :func:`Session.sign`
        """
        self._mech = PyKCS11.LowLevel.CK_MECHANISM()
        self._mech.mechanism = mechanism
        self._param = None
        if param:
            self._param = ckbytelist(param)
            self._mech.pParameter = self._param
            self._mech.ulParameterLen = len(param)

    def to_native(self):
        """convert mechanism to native format"""
        return self._mech


MechanismSHA1 = Mechanism(CKM_SHA_1, None)
MechanismRSAPKCS1 = Mechanism(CKM_RSA_PKCS, None)
MechanismRSAGENERATEKEYPAIR = Mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, None)
MechanismECGENERATEKEYPAIR = Mechanism(CKM_EC_KEY_PAIR_GEN, None)
MechanismAESGENERATEKEY = Mechanism(CKM_AES_KEY_GEN, None)


class AES_GCM_Mechanism:
    """CKM_AES_GCM warpping mechanism"""

    # pylint: disable=too-few-public-methods

    def __init__(self, iv, aad, tagBits):
        """
        :param iv: initialization vector
        :param aad: additional authentication data
        :param tagBits: length of authentication tag in bits
        """
        self._param = PyKCS11.LowLevel.CK_GCM_PARAMS()

        self._source_iv = ckbytelist(iv)
        self._param.pIv = self._source_iv
        self._param.ulIvLen = len(self._source_iv)

        self._source_aad = ckbytelist(aad)
        self._param.pAAD = self._source_aad
        self._param.ulAADLen = len(self._source_aad)

        self._param.ulTagBits = tagBits

        self._mech = PyKCS11.LowLevel.CK_MECHANISM()
        self._mech.mechanism = CKM_AES_GCM
        self._mech.pParameter = self._param
        self._mech.ulParameterLen = PyKCS11.LowLevel.CK_GCM_PARAMS_LENGTH

    def to_native(self):
        """convert mechanism to native format"""
        return self._mech


class AES_CTR_Mechanism:
    """CKM_AES_CTR encryption mechanism"""

    # pylint: disable=too-few-public-methods

    def __init__(self, counterBits, counterBlock):
        """
        :param counterBits: the number of incremented bits in the counter block
        :param counterBlock: a 16-byte initial value of the counter block
        """
        self._param = PyKCS11.LowLevel.CK_AES_CTR_PARAMS()

        self._source_cb = ckbytelist(counterBlock)
        self._param.ulCounterBits = counterBits
        self._param.cb = self._source_cb

        self._mech = PyKCS11.LowLevel.CK_MECHANISM()
        self._mech.mechanism = CKM_AES_CTR
        self._mech.pParameter = self._param
        self._mech.ulParameterLen = PyKCS11.LowLevel.CK_AES_CTR_PARAMS_LENGTH

    def to_native(self):
        """convert mechanism to native format"""
        return self._mech


class RSAOAEPMechanism:
    """RSA OAEP Wrapping mechanism"""

    # pylint: disable=too-few-public-methods

    def __init__(self, hashAlg, mgf, label=None):
        """
        :param hashAlg: the hash algorithm to use (like `CKM_SHA256`)
        :param mgf: the mask generation function to use (like
          `CKG_MGF1_SHA256`)
        :param label: the (optional) label to use
        """
        self._param = PyKCS11.LowLevel.CK_RSA_PKCS_OAEP_PARAMS()
        self._param.hashAlg = hashAlg
        self._param.mgf = mgf
        self._source = None
        self._param.source = CKZ_DATA_SPECIFIED
        if label:
            self._source = ckbytelist(label)
            self._param.ulSourceDataLen = len(self._source)
        else:
            self._param.ulSourceDataLen = 0
        self._param.pSourceData = self._source
        self._mech = PyKCS11.LowLevel.CK_MECHANISM()
        self._mech.mechanism = CKM_RSA_PKCS_OAEP
        self._mech.pParameter = self._param
        self._mech.ulParameterLen = PyKCS11.LowLevel.CK_RSA_PKCS_OAEP_PARAMS_LENGTH

    def to_native(self):
        """convert mechanism to native format"""
        return self._mech


class RSA_PSS_Mechanism:
    """RSA PSS Wrapping mechanism"""

    # pylint: disable=too-few-public-methods

    def __init__(self, mecha, hashAlg, mgf, sLen):
        """
        :param mecha: the mechanism to use (like
          `CKM_SHA384_RSA_PKCS_PSS`)
        :param hashAlg: the hash algorithm to use (like `CKM_SHA384`)
        :param mgf: the mask generation function to use (like
          `CKG_MGF1_SHA384`)
        :param sLen: length, in bytes, of the salt value used in the PSS
          encoding (like 0 or the message length)
        """
        self._param = PyKCS11.LowLevel.CK_RSA_PKCS_PSS_PARAMS()
        self._param.hashAlg = hashAlg
        self._param.mgf = mgf
        self._param.sLen = sLen
        self._mech = PyKCS11.LowLevel.CK_MECHANISM()
        self._mech.mechanism = mecha
        self._mech.pParameter = self._param
        self._mech.ulParameterLen = PyKCS11.LowLevel.CK_RSA_PKCS_PSS_PARAMS_LENGTH

    def to_native(self):
        """convert mechanism to native format"""
        return self._mech


class ECDH1_DERIVE_Mechanism:
    """CKM_ECDH1_DERIVE key derivation mechanism"""

    # pylint: disable=too-few-public-methods

    def __init__(self, publicData, kdf=CKD_NULL, sharedData=None):
        """
        :param publicData: Other party public key which is EC Point [PC || coord-x || coord-y].
        :param kdf: Key derivation function. OPTIONAL. Defaults to CKD_NULL
        :param sharedData: additional shared data. OPTIONAL
        """
        self._param = PyKCS11.LowLevel.CK_ECDH1_DERIVE_PARAMS()

        self._param.kdf = kdf

        if sharedData:
            self._shared_data = ckbytelist(sharedData)
            self._param.pSharedData = self._shared_data
            self._param.ulSharedDataLen = len(self._shared_data)
        else:
            self._source_shared_data = None
            self._param.ulSharedDataLen = 0

        self._public_data = ckbytelist(publicData)
        self._param.pPublicData = self._public_data
        self._param.ulPublicDataLen = len(self._public_data)

        self._mech = PyKCS11.LowLevel.CK_MECHANISM()
        self._mech.mechanism = CKM_ECDH1_DERIVE
        self._mech.pParameter = self._param
        self._mech.ulParameterLen = PyKCS11.LowLevel.CK_ECDH1_DERIVE_PARAMS_LENGTH

    def to_native(self):
        """convert mechanism to native format"""
        return self._mech


class CONCATENATE_BASE_AND_KEY_Mechanism:
    """CKM_CONCATENATE_BASE_AND_KEY key derivation mechanism"""

    # pylint: disable=too-few-public-methods

    def __init__(self, encKey):
        """
        :param encKey: a handle of encryption key
        """
        self._encKey = encKey

        self._mech = PyKCS11.LowLevel.CK_MECHANISM()
        self._mech.mechanism = CKM_CONCATENATE_BASE_AND_KEY
        self._mech.pParameter = self._encKey
        self._mech.ulParameterLen = PyKCS11.LowLevel.CK_OBJECT_HANDLE_LENGTH

    def to_native(self):
        """convert mechanism to native format"""
        return self._mech


class KEY_DERIVATION_STRING_DATA_MechanismBase:
    """Base class for mechanisms using derivation string data"""

    # pylint: disable=too-few-public-methods

    def __init__(self, data, mechType):
        """
        :param data: a byte array to concatenate the key with
        :param mechType: mechanism type
        """
        self._param = PyKCS11.LowLevel.CK_KEY_DERIVATION_STRING_DATA()

        self._data = ckbytelist(data)
        self._param.pData = self._data
        self._param.ulLen = len(self._data)

        self._mech = PyKCS11.LowLevel.CK_MECHANISM()
        self._mech.mechanism = mechType
        self._mech.pParameter = self._param
        self._mech.ulParameterLen = (
            PyKCS11.LowLevel.CK_KEY_DERIVATION_STRING_DATA_LENGTH
        )

    def to_native(self):
        """convert mechanism to native format"""
        return self._mech


class CONCATENATE_BASE_AND_DATA_Mechanism(KEY_DERIVATION_STRING_DATA_MechanismBase):
    """CKM_CONCATENATE_BASE_AND_DATA key derivation mechanism"""

    # pylint: disable=too-few-public-methods

    def __init__(self, data):
        """
        :param data: a byte array to concatenate the key with
        """
        super().__init__(data, CKM_CONCATENATE_BASE_AND_DATA)


class CONCATENATE_DATA_AND_BASE_Mechanism(KEY_DERIVATION_STRING_DATA_MechanismBase):
    """CKM_CONCATENATE_DATA_AND_BASE key derivation mechanism"""

    # pylint: disable=too-few-public-methods

    def __init__(self, data):
        """
        :param data: a byte array to concatenate the key with
        """
        super().__init__(data, CKM_CONCATENATE_DATA_AND_BASE)


class XOR_BASE_AND_DATA_Mechanism(KEY_DERIVATION_STRING_DATA_MechanismBase):
    """CKM_XOR_BASE_AND_DATA key derivation mechanism"""

    # pylint: disable=too-few-public-methods

    def __init__(self, data):
        """
        :param data: a byte array to xor the key with
        """
        super().__init__(data, CKM_XOR_BASE_AND_DATA)


class EXTRACT_KEY_FROM_KEY_Mechanism:
    """CKM_EXTRACT_KEY_FROM_KEY key derivation mechanism"""

    # pylint: disable=too-few-public-methods

    def __init__(self, extractParams):
        """
        :param extractParams: the index of the first bit of the original
        key to be used in the newly-derived key.  For example if
        extractParams=5 then the 5 first bits are skipped and not used.
        """
        self._param = PyKCS11.LowLevel.CK_EXTRACT_PARAMS()
        self._param.assign(extractParams)

        self._mech = PyKCS11.LowLevel.CK_MECHANISM()
        self._mech.mechanism = CKM_EXTRACT_KEY_FROM_KEY
        self._mech.pParameter = self._param
        self._mech.ulParameterLen = PyKCS11.LowLevel.CK_EXTRACT_PARAMS_LENGTH

    def to_native(self):
        """convert mechanism to native format"""
        return self._mech


class EDDSA_Mechanism:
    """CKM_EDDSA signature mechanism"""

    # pylint: disable=too-few-public-methods

    def __init__(self, phFlag=None, contextData=None):
        """
        :param phFlag: prehash flag [True|False]. If this parameter is not set,
        Ed25519 in pure mode without context is assumed.
        :param context: context data (optional)
        """
        self._param = PyKCS11.LowLevel.CK_EDDSA_PARAMS()
        self._mech = PyKCS11.LowLevel.CK_MECHANISM()
        self._mech.mechanism = CKM_EDDSA

        if not phFlag is None:
            self._phFlag = phFlag
            self._param.phFlag = self._phFlag

            if contextData:
                self._contextData = ckbytelist(contextData)
                self._param.pContextData = self._contextData
                self._param.ulContextDataLen = len(self._contextData)

            self._mech.pParameter = self._param
            self._mech.ulParameterLen = PyKCS11.LowLevel.CK_EDDSA_PARAMS_LENGTH

    def to_native(self):
        """convert mechanism to native format"""
        return self._mech


class DigestSession:
    """Digest session"""

    def __init__(self, lib, session, mecha):
        self._lib = lib
        self._session = session
        self._mechanism = mecha.to_native()
        rv = self._lib.C_DigestInit(self._session, self._mechanism)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def update(self, data):
        """
        C_DigestUpdate

        :param data: data to add to the digest
        :type data: bytes or string
        """
        data1 = ckbytelist(data)
        rv = self._lib.C_DigestUpdate(self._session, data1)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return self

    def digestKey(self, handle):
        """
        C_DigestKey

        :param handle: key handle
        :type handle: CK_OBJECT_HANDLE
        """
        rv = self._lib.C_DigestKey(self._session, handle)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return self

    def final(self):
        """
        C_DigestFinal

        :return: the digest
        :rtype: ckbytelist
        """
        digest = ckbytelist()
        # Get the size of the digest
        rv = self._lib.C_DigestFinal(self._session, digest)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        # Get the actual digest
        rv = self._lib.C_DigestFinal(self._session, digest)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return digest


class Session:
    """Manage :func:`PyKCS11Lib.openSession` objects"""

    # pylint: disable=too-many-public-methods

    def __init__(self, pykcs11, session):
        """
        :param pykcs11: PyKCS11 library object
        :type pykcs11: PyKCS11Lib
        :param session: session handle
        :type session: instance of :class:`CK_SESSION_HANDLE`
        """
        if not isinstance(pykcs11, PyKCS11Lib):
            raise TypeError("pykcs11 must be a PyKCS11Lib")
        if not isinstance(session, PyKCS11.LowLevel.CK_SESSION_HANDLE):
            raise TypeError("session must be a CK_SESSION_HANDLE")

        # hold the PyKCS11Lib reference, so that it's not Garbage Collection'd
        self.pykcs11 = pykcs11
        self.session = session

    @property
    def lib(self):
        """
        Get the low level lib of the owning PyKCS11Lib
        """
        return self.pykcs11.lib

    def closeSession(self):
        """
        C_CloseSession
        """
        rv = self.lib.C_CloseSession(self.session)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def getSessionInfo(self):
        """
        C_GetSessionInfo

        :return: a :class:`CK_SESSION_INFO` object
        """
        sessioninfo = PyKCS11.LowLevel.CK_SESSION_INFO()
        rv = self.lib.C_GetSessionInfo(self.session, sessioninfo)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        s = CK_SESSION_INFO()
        s.slotID = sessioninfo.slotID
        s.state = sessioninfo.state
        s.flags = sessioninfo.flags
        s.ulDeviceError = sessioninfo.ulDeviceError
        return s

    def login(self, pin, user_type=CKU_USER):
        """
        C_Login

        :param pin: the user's PIN or None for CKF_PROTECTED_AUTHENTICATION_PATH
        :type pin: string
        :param user_type: the user type. The default value is
          CKU_USER. You may also use CKU_SO
        :type user_type: integer
        """
        pin1 = ckbytelist(pin)
        rv = self.lib.C_Login(self.session, user_type, pin1)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def logout(self):
        """
        C_Logout
        """
        rv = self.lib.C_Logout(self.session)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        del self

    def initPin(self, pin):
        """
        C_InitPIN

        :param pin: new PIN
        """
        new_pin1 = ckbytelist(pin)
        rv = self.lib.C_InitPIN(self.session, new_pin1)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def setPin(self, old_pin, new_pin):
        """
        C_SetPIN

        :param old_pin: old PIN
        :param new_pin: new PIN
        """
        old_pin1 = ckbytelist(old_pin)
        new_pin1 = ckbytelist(new_pin)
        rv = self.lib.C_SetPIN(self.session, old_pin1, new_pin1)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def createObject(self, template):
        """
        C_CreateObject

        :param template: object template
        """
        attrs = self._template2ckattrlist(template)
        handle = PyKCS11.LowLevel.CK_OBJECT_HANDLE()
        rv = self.lib.C_CreateObject(self.session, attrs, handle)
        if rv != PyKCS11.CKR_OK:
            raise PyKCS11.PyKCS11Error(rv)
        return handle

    def destroyObject(self, obj):
        """
        C_DestroyObject

        :param obj: object ID
        """
        rv = self.lib.C_DestroyObject(self.session, obj)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def digestSession(self, mecha=MechanismSHA1):
        """
        C_DigestInit/C_DigestUpdate/C_DigestKey/C_DigestFinal

        :param mecha: the digesting mechanism to be used
          (use `MechanismSHA1` for `CKM_SHA_1`)
        :type mecha: :class:`Mechanism`
        :return: A :class:`DigestSession` object
        :rtype: DigestSession
        """
        return DigestSession(self.lib, self.session, mecha)

    def digest(self, data, mecha=MechanismSHA1):
        """
        C_DigestInit/C_Digest

        :param data: the data to be digested
        :type data:  (binary) sring or list/tuple of bytes
        :param mecha: the digesting mechanism to be used
          (use `MechanismSHA1` for `CKM_SHA_1`)
        :type mecha: :class:`Mechanism`
        :return: the computed digest
        :rtype: ckbytelist

        :note: the returned value is an istance of :class:`ckbytelist`.
          You can easly convert it to a binary string with:
          ``bytes(ckbytelistDigest)``
          or, for Python 2:
          ``''.join(chr(i) for i in ckbytelistDigest)``

        """
        digest = ckbytelist()
        m = mecha.to_native()
        data1 = ckbytelist(data)
        rv = self.lib.C_DigestInit(self.session, m)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        # first call get digest size
        rv = self.lib.C_Digest(self.session, data1, digest)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        # second call get actual digest data
        rv = self.lib.C_Digest(self.session, data1, digest)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return digest

    def sign(self, key, data, mecha=MechanismRSAPKCS1):
        """
        C_SignInit/C_Sign

        :param key: a key handle, obtained calling :func:`findObjects`.
        :type key: PyKCS11.LowLevel.CK_OBJECT_HANDLE
        :param data: the data to be signed
        :type data:  (binary) string or list/tuple of bytes
        :param mecha: the signing mechanism to be used
          (use `MechanismRSAPKCS1` for `CKM_RSA_PKCS`)
        :type mecha: :class:`Mechanism`
        :return: the computed signature
        :rtype: ckbytelist

        :note: the returned value is an instance of :class:`ckbytelist`.
          You can easly convert it to a binary string with:
          ``bytes(ckbytelistSignature)``
          or, for Python 2:
          ``''.join(chr(i) for i in ckbytelistSignature)``

        """
        m = mecha.to_native()
        signature = ckbytelist()
        data1 = ckbytelist(data)
        rv = self.lib.C_SignInit(self.session, m, key)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        # first call get signature size
        rv = self.lib.C_Sign(self.session, data1, signature)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        # second call get actual signature data
        rv = self.lib.C_Sign(self.session, data1, signature)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return signature

    def verify(self, key, data, signature, mecha=MechanismRSAPKCS1):
        """
        C_VerifyInit/C_Verify

        :param key: a key handle, obtained calling :func:`findObjects`.
        :type key: PyKCS11.LowLevel.CK_OBJECT_HANDLE
        :param data: the data that was signed
        :type data:  (binary) string or list/tuple of bytes
        :param signature: the signature to be verified
        :type signature:  (binary) string or list/tuple of bytes
        :param mecha: the signing mechanism to be used
          (use `MechanismRSAPKCS1` for `CKM_RSA_PKCS`)
        :type mecha: :class:`Mechanism`
        :return: True if signature is valid, False otherwise
        :rtype: bool

        """
        m = mecha.to_native()
        data1 = ckbytelist(data)
        rv = self.lib.C_VerifyInit(self.session, m, key)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        rv = self.lib.C_Verify(self.session, data1, signature)
        if rv == CKR_OK:
            return True
        if rv == CKR_SIGNATURE_INVALID:
            return False
        raise PyKCS11Error(rv)

    def encrypt(self, key, data, mecha=MechanismRSAPKCS1):
        """
        C_EncryptInit/C_Encrypt

        :param key: a key handle, obtained calling :func:`findObjects`.
        :type key: PyKCS11.LowLevel.CK_OBJECT_HANDLE
        :param data: the data to be encrypted
        :type data:  (binary) string or list/tuple of bytes
        :param mecha: the encryption mechanism to be used
          (use `MechanismRSAPKCS1` for `CKM_RSA_PKCS`)
        :type mecha: :class:`Mechanism`
        :return: the encrypted data
        :rtype: ckbytelist

        :note: the returned value is an instance of :class:`ckbytelist`.
          You can easly convert it to a binary string with:
          ``bytes(ckbytelistEncrypted)``
          or, for Python 2:
          ``''.join(chr(i) for i in ckbytelistEncrypted)``

        """
        encrypted = ckbytelist()
        m = mecha.to_native()
        data1 = ckbytelist(data)
        rv = self.lib.C_EncryptInit(self.session, m, key)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        # first call get encrypted size
        rv = self.lib.C_Encrypt(self.session, data1, encrypted)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        # second call get actual encrypted data
        rv = self.lib.C_Encrypt(self.session, data1, encrypted)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return encrypted

    def encryptInit(self, mech, key):
        """
        C_EncryptInit

        :param mech: the encryption mechanism to be used
        :type mech: instance of :class:`Mechanism`
        :param key: a key handle
        :type key: integer
        """
        m = mech.to_native()
        rv = self.lib.C_EncryptInit(self.session, m, key)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def encryptUpdate(self, data):
        """
        C_EncryptUpdate

        :param data: the data to be encrypted
        :type data: (binary) string or list/tuple of bytes
        """
        encrypted = ckbytelist()
        data1 = ckbytelist(data)
        rv = self.lib.C_EncryptUpdate(self.session, data1, encrypted)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return encrypted

    def encryptFinal(self):
        """
        C_EncryptFinal

        :return: the last part of data to be encrypted
        :rtype: (binary) string or list/tuple of bytes
        """
        encrypted = ckbytelist()
        rv = self.lib.C_EncryptFinal(self.session, encrypted)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return encrypted

    def decrypt(self, key, data, mecha=MechanismRSAPKCS1):
        """
        C_DecryptInit/C_Decrypt

        :param key: a key handle, obtained calling :func:`findObjects`.
        :type key: PyKCS11.LowLevel.CK_OBJECT_HANDLE
        :param data: the data to be decrypted
        :type data:  (binary) string or list/tuple of bytes
        :param mecha: the decrypt mechanism to be used
        :type mecha: :class:`Mechanism` instance or :class:`MechanismRSAPKCS1`
          for CKM_RSA_PKCS
        :return: the decrypted data
        :rtype: ckbytelist

        :note: the returned value is an instance of :class:`ckbytelist`.
          You can easly convert it to a binary string with:
          ``bytes(ckbytelistData)``
          or, for Python 2:
          ``''.join(chr(i) for i in ckbytelistData)``

        """
        m = mecha.to_native()
        decrypted = ckbytelist()
        data1 = ckbytelist(data)
        rv = self.lib.C_DecryptInit(self.session, m, key)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        # first call get decrypted size
        rv = self.lib.C_Decrypt(self.session, data1, decrypted)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        # second call get actual decrypted data
        rv = self.lib.C_Decrypt(self.session, data1, decrypted)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return decrypted

    def decryptInit(self, mech, key):
        """
        C_DecryptInit

        :param mech: the decrypt mechanism to be used
        :type mech: instance of :class:`Mechanism`
        :param key: a key handle
        :type key: integer
        """
        m = mech.to_native()
        rv = self.lib.C_DecryptInit(self.session, m, key)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def decryptUpdate(self, data):
        """
        C_DecryptUpdate

        :param data: the data to be decrypted
        :type data: (binary) string or list/tuple of bytes
        """
        decrypted = ckbytelist()
        encrypted = ckbytelist(data)
        rv = self.lib.C_DecryptUpdate(self.session, encrypted, decrypted)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return decrypted

    def decryptFinal(self):
        """
        C_DecryptFinal

        :return: the last part of the decrypted data
        :rtype: (binary) string or list/tuple of bytes
        """
        decrypted = ckbytelist()
        rv = self.lib.C_DecryptFinal(self.session, decrypted)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return decrypted

    def wrapKey(self, wrappingKey, key, mecha=MechanismRSAPKCS1):
        """
        C_WrapKey

        :param wrappingKey: a wrapping key handle
        :type wrappingKey: PyKCS11.LowLevel.CK_OBJECT_HANDLE
        :param key: a handle of the key to be wrapped
        :type key: PyKCS11.LowLevel.CK_OBJECT_HANDLE
        :param mecha: the encrypt mechanism to be used
          (use `MechanismRSAPKCS1` for `CKM_RSA_PKCS`)
        :type mecha: :class:`Mechanism`
        :return: the wrapped key bytes
        :rtype: ckbytelist

        :note: the returned value is an instance of :class:`ckbytelist`.
          You can easily convert it to a binary string with:
          ``bytes(ckbytelistData)``
          or, for Python 2:
          ``''.join(chr(i) for i in ckbytelistData)``

        """
        wrapped = ckbytelist()
        native = mecha.to_native()
        # first call get wrapped size
        rv = self.lib.C_WrapKey(self.session, native, wrappingKey, key, wrapped)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        # second call get actual wrapped key data
        rv = self.lib.C_WrapKey(self.session, native, wrappingKey, key, wrapped)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return wrapped

    def unwrapKey(self, unwrappingKey, wrappedKey, template, mecha=MechanismRSAPKCS1):
        """
        C_UnwrapKey

        :param unwrappingKey: the unwrapping key handle
        :type unwrappingKey: PyKCS11.LowLevel.CK_OBJECT_HANDLE
        :param wrappedKey: the bytes of the wrapped key
        :type wrappedKey:  (binary) string or list/tuple of bytes
        :param template: template for the unwrapped key
        :param mecha: the decrypt mechanism to be used (use
          `MechanismRSAPKCS1` for `CKM_RSA_PKCS`)
        :type mecha: :class:`Mechanism`
        :return: the unwrapped key object
        :rtype: PyKCS11.LowLevel.CK_OBJECT_HANDLE

        """
        m = mecha.to_native()
        data1 = ckbytelist(wrappedKey)
        handle = PyKCS11.LowLevel.CK_OBJECT_HANDLE()
        attrs = self._template2ckattrlist(template)
        rv = self.lib.C_UnwrapKey(self.session, m, unwrappingKey, data1, attrs, handle)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return handle

    def deriveKey(self, baseKey, template, mecha):
        """
        C_DeriveKey

        :param baseKey: the base key handle
        :type baseKey: PyKCS11.LowLevel.CK_OBJECT_HANDLE
        :param template: template for the unwrapped key
        :param mecha: the decrypt mechanism to be used (use
          `ECDH1_DERIVE_Mechanism(...)` for `CKM_ECDH1_DERIVE`)
        :type mecha: :class:`Mechanism`
        :return: the unwrapped key object
        :rtype: PyKCS11.LowLevel.CK_OBJECT_HANDLE
        """
        m = mecha.to_native()
        handle = PyKCS11.LowLevel.CK_OBJECT_HANDLE()
        attrs = self._template2ckattrlist(template)
        rv = self.lib.C_DeriveKey(self.session, m, baseKey, attrs, handle)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return handle

    def isNum(self, p11_type):
        """
        is the type a numerical value?

        :param p11_type: PKCS#11 type like `CKA_CERTIFICATE_TYPE`
        :rtype: bool
        """
        if p11_type in (
            CKA_CERTIFICATE_TYPE,
            CKA_CLASS,
            CKA_HW_FEATURE_TYPE,
            CKA_KEY_GEN_MECHANISM,
            CKA_KEY_TYPE,
            CKA_MODULUS_BITS,
            CKA_VALUE_BITS,
            CKA_VALUE_LEN,
        ):
            return True
        return False

    def isString(self, p11_type):
        """
        is the type a string value?

        :param p11_type: PKCS#11 type like `CKA_LABEL`
        :rtype: bool
        """
        if p11_type in (CKA_LABEL, CKA_APPLICATION):
            return True
        return False

    def isBool(self, p11_type):
        """
        is the type a boolean value?

        :param p11_type: PKCS#11 type like `CKA_ALWAYS_SENSITIVE`
        :rtype: bool
        """
        if p11_type in (
            CKA_ALWAYS_AUTHENTICATE,
            CKA_ALWAYS_SENSITIVE,
            CKA_DECRYPT,
            CKA_DERIVE,
            CKA_ENCRYPT,
            CKA_EXTRACTABLE,
            CKA_HAS_RESET,
            CKA_LOCAL,
            CKA_MODIFIABLE,
            CKA_COPYABLE,
            CKA_DESTROYABLE,
            CKA_NEVER_EXTRACTABLE,
            CKA_PRIVATE,
            CKA_RESET_ON_INIT,
            CKA_SECONDARY_AUTH,
            CKA_SENSITIVE,
            CKA_SIGN,
            CKA_SIGN_RECOVER,
            CKA_TOKEN,
            CKA_TRUSTED,
            CKA_UNWRAP,
            CKA_VERIFY,
            CKA_VERIFY_RECOVER,
            CKA_WRAP,
            CKA_WRAP_WITH_TRUSTED,
        ):
            return True
        return False

    def isBin(self, p11_type):
        """
        is the type a byte array value?

        :param p11_type: PKCS#11 type like `CKA_MODULUS`
        :rtype: bool
        """
        return (
            (not self.isBool(p11_type))
            and (not self.isString(p11_type))
            and (not self.isNum(p11_type))
        )

    def isAttributeList(self, p11_type):
        """
        is the type a attribute list value?

        :param p11_type: PKCS#11 type like `CKA_WRAP_TEMPLATE`
        :rtype: bool
        """
        if p11_type in (CKA_WRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE):
            return True
        return False

    def _template2ckattrlist(self, template):
        t = PyKCS11.LowLevel.ckattrlist(len(template))
        for x, attr in enumerate(template):
            if self.isNum(attr[0]):
                t[x].SetNum(attr[0], int(attr[1]))
            elif self.isString(attr[0]):
                t[x].SetString(attr[0], str(attr[1]))
            elif self.isBool(attr[0]):
                t[x].SetBool(attr[0], attr[1] == CK_TRUE)
            elif self.isAttributeList(attr[0]):
                t[x].SetList(attr[0], self._template2ckattrlist(attr[1]))
            elif self.isBin(attr[0]):
                attrBin = attr[1]
                attrStr = attr[1]
                if isinstance(attr[1], int):
                    attrStr = str(attr[1])
                if isinstance(attr[1], bytes):
                    attrBin = ckbytelist(attrStr)
                t[x].SetBin(attr[0], attrBin)
            else:
                raise PyKCS11Error(-2, f"attr: {attr[0]:08X}")
        return t

    def generateKey(self, template, mecha=MechanismAESGENERATEKEY):
        """
        generate a secret key

        :param template: template for the secret key
        :param mecha: mechanism to use
        :return: handle of the generated key
        :rtype: PyKCS11.LowLevel.CK_OBJECT_HANDLE
        """
        t = self._template2ckattrlist(template)
        ck_handle = PyKCS11.LowLevel.CK_OBJECT_HANDLE()
        m = mecha.to_native()
        rv = self.lib.C_GenerateKey(self.session, m, t, ck_handle)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return ck_handle

    def generateKeyPair(
        self, templatePub, templatePriv, mecha=MechanismRSAGENERATEKEYPAIR
    ):
        """
        generate a key pair

        :param templatePub: template for the public key
        :param templatePriv:  template for the private key
        :param mecha: mechanism to use
        :return: a tuple of handles (pub, priv)
        :rtype: tuple
        """
        tPub = self._template2ckattrlist(templatePub)
        tPriv = self._template2ckattrlist(templatePriv)
        ck_pub_handle = PyKCS11.LowLevel.CK_OBJECT_HANDLE()
        ck_prv_handle = PyKCS11.LowLevel.CK_OBJECT_HANDLE()
        m = mecha.to_native()
        rv = self.lib.C_GenerateKeyPair(
            self.session, m, tPub, tPriv, ck_pub_handle, ck_prv_handle
        )

        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return ck_pub_handle, ck_prv_handle

    def findObjects(self, template=()):
        """
        find the objects matching the template pattern

        :param template: list of attributes tuples (attribute,value).
          The default value is () and all the objects are returned
        :type template: list
        :return: a list of object ids
        :rtype: list
        """
        t = self._template2ckattrlist(template)

        # we search for 10 objects by default. speed/memory tradeoff
        result = PyKCS11.LowLevel.ckulonglist(10)

        rv = self.lib.C_FindObjectsInit(self.session, t)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        res = []
        while True:
            rv = self.lib.C_FindObjects(self.session, result)
            if rv != CKR_OK:
                raise PyKCS11Error(rv)
            for x in result:
                # make a copy of the handle: the original value get
                # corrupted (!!)
                a = CK_OBJECT_HANDLE(self)
                a.assign(x)
                res.append(a)
            if len(result) == 0:
                break

        rv = self.lib.C_FindObjectsFinal(self.session)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return res

    def getAttributeValue(self, obj_id, attr, allAsBinary=False):
        """
        C_GetAttributeValue

        :param obj_id: object ID returned by :func:`findObjects`
        :type obj_id: PyKCS11.LowLevel.CK_OBJECT_HANDLE
        :param attr: list of attributes
        :type attr: list
        :param allAsBinary: return all values as binary data; default is False.
        :type allAsBinary: Boolean
        :return: a list of values corresponding to the list of attributes
        :rtype: list

        :see: :func:`getAttributeValue_fragmented`

        :note: if allAsBinary is True the function do not convert results to
          Python types (i.e.: CKA_TOKEN to Bool, CKA_CLASS to int, ...).

          Binary data is returned as :class:`ckbytelist` type, usable
          as a list containing only bytes.
          You can easly convert it to a binary string with:
          ``bytes(ckbytelistVariable)``
          or, for Python 2:
          ``''.join(chr(i) for i in ckbytelistVariable)``

        """
        valTemplate = PyKCS11.LowLevel.ckattrlist(len(attr))
        for index, value in enumerate(attr):
            valTemplate[index].SetType(value)
        # first call to get the attribute size and reserve the memory
        rv = self.lib.C_GetAttributeValue(self.session, obj_id, valTemplate)
        if rv in (
            CKR_ATTRIBUTE_TYPE_INVALID,
            CKR_ATTRIBUTE_SENSITIVE,
            CKR_ARGUMENTS_BAD,
        ):
            return self.getAttributeValue_fragmented(obj_id, attr, allAsBinary)

        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        # second call to get the attribute value
        rv = self.lib.C_GetAttributeValue(self.session, obj_id, valTemplate)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        res = []
        for x in range(len(attr)):
            if allAsBinary:
                res.append(valTemplate[x].GetBin())
            elif valTemplate[x].IsNum():
                res.append(valTemplate[x].GetNum())
            elif valTemplate[x].IsBool():
                res.append(valTemplate[x].GetBool())
            elif valTemplate[x].IsString():
                res.append(valTemplate[x].GetString())
            elif valTemplate[x].IsBin():
                res.append(valTemplate[x].GetBin())
            else:
                raise PyKCS11Error(-2, f"valTemplate: {valTemplate[x]:08X}")

        return res

    def getAttributeValue_fragmented(self, obj_id, attr, allAsBinary=False):
        """
        Same as :func:`getAttributeValue` except that when some attribute
        is sensitive or unknown an empty value (None) is returned.

        Note: this is achived by getting attributes one by one.

        :see: :func:`getAttributeValue`
        """
        # some attributes does not exists or is sensitive
        # but we don't know which ones. So try one by one
        valTemplate = PyKCS11.LowLevel.ckattrlist(1)
        res = []
        for elt in attr:
            valTemplate[0].Reset()
            valTemplate[0].SetType(elt)
            # first call to get the attribute size and reserve the memory
            rv = self.lib.C_GetAttributeValue(self.session, obj_id, valTemplate)
            if rv in (
                CKR_ATTRIBUTE_TYPE_INVALID,
                CKR_ATTRIBUTE_SENSITIVE,
                CKR_ARGUMENTS_BAD,
            ):
                # append an empty value
                res.append(None)
                continue

            if rv != CKR_OK:
                raise PyKCS11Error(rv)
            # second call to get the attribute value
            rv = self.lib.C_GetAttributeValue(self.session, obj_id, valTemplate)
            if rv != CKR_OK:
                raise PyKCS11Error(rv)

            if allAsBinary:
                res.append(valTemplate[0].GetBin())
            elif valTemplate[0].IsNum():
                res.append(valTemplate[0].GetNum())
            elif valTemplate[0].IsBool():
                res.append(valTemplate[0].GetBool())
            elif valTemplate[0].IsString():
                res.append(valTemplate[0].GetString())
            elif valTemplate[0].IsBin():
                res.append(valTemplate[0].GetBin())
            elif valTemplate[0].IsAttributeList():
                res.append(valTemplate[0].GetBin())
            else:
                raise PyKCS11Error(-2)

        return res

    def setAttributeValue(self, obj_id, template):
        """
        C_SetAttributeValue

        :param obj_id: object ID returned by :func:`findObjects`
        :type obj_id: PyKCS11.LowLevel.CK_OBJECT_HANDLE
        :param template: list of (attribute, value) pairs
        :type template: list
        :return: Nothing
        :rtype: None
        """

        templ = self._template2ckattrlist(template)
        rv = self.lib.C_SetAttributeValue(self.session, obj_id, templ)

        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def seedRandom(self, seed):
        """
        C_SeedRandom

        :param seed: seed material
        :type seed: iterable
        """
        low_seed = ckbytelist(seed)
        rv = self.lib.C_SeedRandom(self.session, low_seed)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def generateRandom(self, size=16):
        """
        C_GenerateRandom

        :param size: number of random bytes to get
        :type size: integer

        :note: the returned value is an instance of :class:`ckbytelist`.
          You can easly convert it to a binary string with:
          ``bytes(random)``
          or, for Python 2:
          ``''.join(chr(i) for i in random)``
        """
        low_rand = ckbytelist([0] * size)
        rv = self.lib.C_GenerateRandom(self.session, low_rand)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return low_rand
