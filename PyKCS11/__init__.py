#   Copyright (C) 2006-2015 Ludovic Rousseau (ludovic.rousseau@free.fr)
#   Copyright (C) 2010 Giuseppe Amato (additions to original interface)
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.

from __future__ import print_function

import PyKCS11.LowLevel
import os
import sys

PY3 = sys.version_info[0] >= 3
if PY3:
    def byte_to_int(byte):
        return byte

    def to_param_string(param):
        if isinstance(param, str):
            return bytes(param, 'ascii')
        else:
            return bytes(param)
else:
    def byte_to_int(byte):
        return ord(byte)

    def to_param_string(param):
        if isinstance(param, str):
            return param
        else:
            return str(bytearray(param))

    range = xrange

# redefine PKCS#11 constants
CK_TRUE = PyKCS11.LowLevel.CK_TRUE
CK_FALSE = PyKCS11.LowLevel.CK_FALSE
CK_UNAVAILABLE_INFORMATION = PyKCS11.LowLevel.CK_UNAVAILABLE_INFORMATION
CK_EFFECTIVELY_INFINITE = PyKCS11.LowLevel.CK_EFFECTIVELY_INFINITE
CK_INVALID_HANDLE = PyKCS11.LowLevel.CK_INVALID_HANDLE

CKM = {}
CKR = {}
CKA = {}
CKO = {}
CKU = {}
CKK = {}
CKC = {}
CKF = {}
CKS = {}
CKG = {}
CKZ = {}

# redefine PKCS#11 constants using well known prefixes
for x in PyKCS11.LowLevel.__dict__.keys():
    if x[:4] == 'CKM_' \
      or x[:4] == 'CKR_' \
      or x[:4] == 'CKA_' \
      or x[:4] == 'CKO_' \
      or x[:4] == 'CKU_' \
      or x[:4] == 'CKK_' \
      or x[:4] == 'CKC_' \
      or x[:4] == 'CKF_' \
      or x[:4] == 'CKS_' \
      or x[:4] == 'CKG_' \
      or x[:4] == 'CKZ_':
        a = "%s=PyKCS11.LowLevel.%s" % (x, x)
        exec(a)
        if x[3:] != "_VENDOR_DEFINED":
            eval(x[:3])[eval(x)] = x  # => CKM[CKM_RSA_PKCS] = 'CKM_RSA_PKCS'
            eval(x[:3])[x] = eval(x)  # => CKM['CKM_RSA_PKCS'] = CKM_RSA_PKCS

# special CKR[] values
CKR[-2] = "Unkown PKCS#11 type"
CKR[-1] = "Load"


class ckbytelist(PyKCS11.LowLevel.ckbytelist):
    """
    add a __repr__() method to the LowLevel equivalent
    """

    def __repr__(self):
        """
        return the representation of a tuple
        the __str__ method will use it also
        """
        rep = [elt for elt in self]
        return repr(rep)


class CK_OBJECT_HANDLE(PyKCS11.LowLevel.CK_OBJECT_HANDLE):
    """
    add a __repr__() method to the LowLevel equivalent
    """

    def __init__(self, session):
        PyKCS11.LowLevel.CK_OBJECT_HANDLE.__init__(self)
        self.session = session
        pass

    def to_dict(self):
        """
        convert the fields of the object into a dictionnary
        """
        # all the attibutes defined by PKCS#11
        all_attributes = PyKCS11.CKA.keys()

        # only use the integer values and not the strings like 'CKM_RSA_PKCS'
        all_attributes = [attr for attr in all_attributes if
            isinstance(attr, int)]

        # all the attributes of the object
        attributes = self.session.getAttributeValue(self, all_attributes)

        dico = dict()
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
        lines = list()
        for key in sorted(dico.keys()):
            lines.append("%s: %s" % (key, dico[key]))
        return "\n".join(lines)


class CkClass(object):
    """
    Base class for CK_* classes
    """

    # dictionnary of integer_value: text_value for the flags bits
    flags_dict = dict()

    # dictionnary of fields names and types
    # type can be "pair", "flags" or "text"
    fields = dict()

    flags = 0

    def flags2text(self):
        """
        parse the L{self.flags} field and create a list of "CKF_*" strings
        corresponding to bits set in flags

        @return: a list of strings
        @rtype: list
        """
        r = []
        for v in self.flags_dict.keys():
            if self.flags & v:
                r.append(self.flags_dict[v])
        return r

    def to_dict(self):
        """
        convert the fields of the object into a dictionnary
        """
        dico = dict()
        for field in self.fields.keys():
            if field == "flags":
                dico[field] = self.flags2text()
            else:
                dico[field] = eval("self." + field)
        return dico

    def __str__(self):
        """
        text representation of the object
        """
        dico = self.to_dict()
        lines = list()
        for key in sorted(dico.keys()):
            type = self.fields[key]
            if type == "flags":
                lines.append("%s: %s" % (key, ", ".join(dico[key])))
            elif type == "pair":
                lines.append("%s: " % key + "%d.%d" % dico[key])
            else:
                lines.append("%s: %s" % (key, dico[key]))
        return "\n".join(lines)


class CK_SLOT_INFO(CkClass):
    """
    matches the PKCS#11 CK_SLOT_INFO structure

    @ivar slotDescription: blank padded
    @type slotDescription: string
    @ivar manufacturerID: blank padded
    @type manufacturerID: string
    @ivar flags: See L{flags2text}
    @type flags: integer
    @ivar hardwareVersion: 2 elements list
    @type hardwareVersion: list
    @ivar firmwareVersion: 2 elements list
    @type firmwareVersion: list
    """

    flags_dict = {
        CKF_TOKEN_PRESENT: "CKF_TOKEN_PRESENT",
        CKF_REMOVABLE_DEVICE: "CKF_REMOVABLE_DEVICE",
        CKF_HW_SLOT: "CKF_HW_SLOT"}

    fields = {"slotDescription": "text",
        "manufacturerID": "text",
        "flags": "flags",
        "hardwareVersion": "text",
        "firmwareVersion": "text"}


class CK_INFO(CkClass):
    """
    matches the PKCS#11 CK_INFO structure

    @ivar cryptokiVersion: Cryptoki interface version
    @type cryptokiVersion: integer
    @ivar manufacturerID: blank padded
    @type manufacturerID: string
    @ivar flags: must be zero
    @type flags: integer
    @ivar libraryDescription: blank padded
    @type libraryDescription: string
    @ivar libraryVersion: 2 elements list
    @type libraryVersion: list
    """

    fields = {"cryptokiVersion": "pair",
        "manufacturerID": "text",
        "flags": "flags",
        "libraryDescription": "text",
        "libraryVersion": "pair"}


class CK_SESSION_INFO(CkClass):
    """
    matches the PKCS#11 CK_SESSION_INFO structure

    @ivar slotID: ID of the slot that interfaces with the token
    @type slotID: integer
    @ivar state: state of the session
    @type state: integer
    @ivar flags: bit flags that define the type of session
    @type flags: integer
    @ivar ulDeviceError: an error code defined by the cryptographic token
    @type ulDeviceError: integer
    """

    flags_dict = {
        CKF_RW_SESSION: "CKF_RW_SESSION",
        CKF_SERIAL_SESSION: "CKF_SERIAL_SESSION",
    }

    def state2text(self):
        """
        parse the L{self.state} field and return a "CKS_*" string
        corresponding to the state

        @return: a string
        @rtype: string
        """
        return CKS[self.state]

    fields = {"slotID": "text",
        "state": "text",
        "flags": "flags",
        "ulDeviceError": "text"}


class CK_TOKEN_INFO(CkClass):
    """
    matches the PKCS#11 CK_TOKEN_INFO structure

    @ivar label: blank padded
    @type label: string
    @ivar manufacturerID: blank padded
    @type manufacturerID: string
    @ivar model: string blank padded
    @type model: string
    @ivar serialNumber: string blank padded
    @type serialNumber: string
    @ivar flags:
    @type flags: integer
    @ivar ulMaxSessionCount:
    @type ulMaxSessionCount: integer
    @ivar ulSessionCount:
    @type ulSessionCount: integer
    @ivar ulMaxRwSessionCount:
    @type ulMaxRwSessionCount: integer
    @ivar ulRwSessionCount:
    @type ulRwSessionCount: integer
    @ivar ulMaxPinLen:
    @type ulMaxPinLen: integer
    @ivar ulMinPinLen:
    @type ulMinPinLen: integer
    @ivar ulTotalPublicMemory:
    @type ulTotalPublicMemory: integer
    @ivar ulFreePublicMemory:
    @type ulFreePublicMemory: integer
    @ivar ulTotalPrivateMemory:
    @type ulTotalPrivateMemory: integer
    @ivar ulFreePrivateMemory:
    @type ulFreePrivateMemory: integer
    @ivar hardwareVersion: 2 elements list
    @type hardwareVersion: list
    @ivar firmwareVersion: 2 elements list
    @type firmwareVersion: list
    @ivar utcTime: string
    @type utcTime: string
    """

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

    fields = {"label": "text",
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
        "utcTime": "text"}


class CK_MECHANISM_INFO(CkClass):
    """
    matches the PKCS#11 CK_MECHANISM_INFO structure

    @ivar ulMinKeySize: minimum size of the key
    @type ulMinKeySize: integer
    @ivar ulMaxKeySize: maximum size of the key
    @type ulMaxKeySize: integer
    @ivar flags: bit flags specifying mechanism capabilities
    @type flags: integer
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

    fields = {"ulMinKeySize": "text",
        "ulMaxKeySize": "text",
        "flags": "flags"}


class PyKCS11Error(Exception):
    """ define the possible PKCS#11 error codes """

    def __init__(self, value, text=""):
        self.value = value
        self.text = text

    def __str__(self):
        """
        The text representation of a PKCS#11 error is something like:
        "CKR_DEVICE_ERROR (0x00000030)"
        """
        if (self.value < 0):
            return CKR[self.value] + " (%s)" % self.text
        else:
            return CKR[self.value] + " (0x%08X)" % self.value


class PyKCS11Lib(object):
    """ high level PKCS#11 binding """

    def __init__(self):
        self.lib = PyKCS11.LowLevel.CPKCS11Lib()

    def __del__(self):
        self.lib.Unload()

    def load(self, pkcs11dll_filename=None, *init_string):
        """
        load a PKCS#11 library

        @type pkcs11dll_filename: string
        @param pkcs11dll_filename: the library name. If this parameter
        is not set the environment variable PYKCS11LIB is used instead
        @return: a L{PyKCS11Lib} object
        @raise PyKCS11Error(-1): when the load fails
        """
        if pkcs11dll_filename is None:
            pkcs11dll_filename = os.getenv("PYKCS11LIB")
            if pkcs11dll_filename is None:
                raise PyKCS11Error(-1, "No PKCS11 library specified (set PYKCS11LIB env variable)")
        rv = self.lib.Load(pkcs11dll_filename, True)
        if rv == 0:
            raise PyKCS11Error(-1, pkcs11dll_filename)

    def initToken(self, slot, pin, label):
        """
        C_InitToken

        @param slot: slot number returned by L{getSlotList}
        @type slot: integer
        @param pin: SO's initial PIN
        @param label: new label of the token
        """
        rv = self.lib.C_InitToken(slot, pin, label)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def getInfo(self):
        """
        C_GetInfo

        @return: a L{CK_INFO} object
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

    def getSlotList(self):
        """
        C_GetSlotList

        @return: a list of available slots
        @rtype: list
        """
        slotList = PyKCS11.LowLevel.ckintlist()
        rv = self.lib.C_GetSlotList(0, slotList)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        s = []
        for x in range(len(slotList)):
            s.append(slotList[x])
        return s

    def getSlotInfo(self, slot):
        """
        C_GetSlotInfo

        @param slot: slot number returned by L{getSlotList}
        @type slot: integer
        @return: a L{CK_SLOT_INFO} object
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

        @param slot: slot number returned by L{getSlotList}
        @type slot: integer
        @return: a L{CK_TOKEN_INFO} object
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
        t.hardwareVersion = (tokeninfo.hardwareVersion.major, tokeninfo.hardwareVersion.minor)
        t.firmwareVersion = (tokeninfo.firmwareVersion.major, tokeninfo.firmwareVersion.minor)
        t.utcTime = tokeninfo.GetUtcTime()

        return t

    def openSession(self, slot, flags=0):
        """
        C_OpenSession

        @param slot: slot number returned by L{getSlotList}
        @type slot: integer
        @param flags: 0 (default), L{CKF_RW_SESSION} for RW session
        @type flags: integer
        @return: a L{Session} object
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

        @param slot: slot number
        @type slot: integer
        """
        rv = self.lib.C_CloseAllSessions(slot)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def getMechanismList(self, slot):
        """
        C_GetMechanismList

        @param slot: slot number returned by L{getSlotList}
        @type slot: integer
        @return: the list of available mechanisms for a slot
        @rtype: list
        """
        mechanismList = PyKCS11.LowLevel.ckintlist()
        rv = self.lib.C_GetMechanismList(slot, mechanismList)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        m = []
        for x in range(len(mechanismList)):
            mechanism = mechanismList[x]
            if mechanism >= CKM_VENDOR_DEFINED:
                k = 'CKR_VENDOR_DEFINED_%X' % (mechanism - CKM_VENDOR_DEFINED)
                CKM[k] = mechanism
                CKM[mechanism] = k
            m.append(CKM[mechanism])
        return m

    def getMechanismInfo(self, slot, type):
        """
        C_GetMechanismInfo

        @param slot: slot number returned by L{getSlotList}
        @type slot: integer
        @param type: a CKM_* type
        @type type: integer
        @return: information about a mechanism
        @rtype: a L{CK_MECHANISM_INFO} object
        """
        info = PyKCS11.LowLevel.CK_MECHANISM_INFO()
        rv = self.lib.C_GetMechanismInfo(slot, CKM[type], info)
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

        @param flags: 0 (default) or CKF_DONT_BLOCK
        @type flags: integer
        @return: slot
        @rtype: integer
        """
        tmp = 0
        (rv, slot) = self.lib.C_WaitForSlotEvent(flags, tmp)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        return slot


class Mechanism(object):
    """Wraps CK_MECHANISM"""

    def __init__(self, mechanism, param=None):
        """
        @param mechanism: the mechanism to be used
        @type mechanism: integer, any CKM_* value
        @param param: data to be used as crypto operation parameter
        (i.e. the IV for some algorithms)
        @type param: string or list/tuple of bytes

        @see: L{Session.decrypt}, L{Session.sign}
        """
        self._mech = PyKCS11.LowLevel.CK_MECHANISM()
        self._mech.mechanism = mechanism
        self._param = None 
        if param:
            self._param = to_param_string(param)
            self._mech.pParameter = self._param 
            self._mech.ulParameterLen = len(param)

    def to_native(self):
        return self._mech

MechanismSHA1 = Mechanism(CKM_SHA_1, None)
MechanismRSAPKCS1 = Mechanism(CKM_RSA_PKCS, None)
MechanismRSAGENERATEKEYPAIR = Mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, None)
MechanismECGENERATEKEYPAIR = Mechanism(CKM_EC_KEY_PAIR_GEN, None)
MechanismAESGENERATEKEY = Mechanism(CKM_AES_KEY_GEN, None)

class RSAOAEPMechanism(object):
    """RSA OAEP Wrapping mechanism"""

    def __init__(self, hash, mgf, label=None):
        """
        @param hash: the hash algorithm to use
        @param mfg: the mask generation function to use
        @param label: the (optional) label to use
        """
        self._param = PyKCS11.LowLevel.CK_RSA_PKCS_OAEP_PARAMS()
        self._param.hashAlg = hash
        self._param.mgf = mgf
        self._source = None
        if label:
            self._param.src = CKZ_DATA_SPECIFIED
            self._source = to_param_string(label)
            self._param.pSourceData = self._source
            self._param.ulSourceDataLen = len(label)
        self._mech = PyKCS11.LowLevel.CK_MECHANISM()
        self._mech.mechanism = CKM_RSA_PKCS_OAEP
        self._mech.pParameter = self._param
        self._mech.ulParameterLen = PyKCS11.LowLevel.CK_RSA_PKCS_OAEP_PARAMS_LENGTH

    def to_native(self):
        return self._mech

class DigestSession(object):
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

        @param data: data to add to the digest
        @type data: bytes or string
        """
        data1 = ckbytelist()
        data1.reserve(len(data))
        if isinstance(data, bytes):
            for x in data:
                data1.append(byte_to_int(x))
        else:
            for c in range(len(data)):
                data1.append(data[c])
        rv = self._lib.C_DigestUpdate(self._session, data1)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return self

    def digestKey(self, handle):
        """
        C_DigestKey

        @param handle: key handle
        @type data: Handle
        """
        rv = self._lib.C_DigestKey(self._session, handle)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return self

    def final(self):
        """
        C_DigestFinal

        @return: the digest
        @rtype: ckbytelist
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

class Session(object):
    """ Manage L{PyKCS11Lib.openSession} objects """

    def __init__(self, pykcs11, session):
        """
        @param pykcs11: PyKCS11 library object
        @type pykcs11: PyKCS11Lib
        @param session: session handle
        @type session: instance of CK_SESSION_HANDLE
        """
        if not isinstance(pykcs11, PyKCS11Lib):
            raise TypeError("pykcs11 must be a PyKCS11Lib")
        if not isinstance(session, LowLevel.CK_SESSION_HANDLE):
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

        @return: a L{CK_SESSION_INFO} object
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

        @param pin: the user's PIN or None for CKF_PROTECTED_AUTHENTICATION_PATH
        @type pin: string
        @param user_type: the user type. The default value is
        CKU_USER. You may also use CKU_SO
        @type user_type: integer
        """
        rv = self.lib.C_Login(self.session, user_type, pin)
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

    def initPin(self, new_pin):
        """
        C_InitPIN

        @param new_pin: new PIN
        """
        rv = self.lib.C_InitPIN(self.session, new_pin)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def setPin(self, old_pin, new_pin):
        """
        C_SetPIN

        @param old_pin: old PIN
        @param new_pin: new PIN
        """
        rv = self.lib.C_SetPIN(self.session, old_pin, new_pin)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def createObject(self, template):
        """
        C_CreateObject

        @param template: object template
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

        @param obj: object ID
        """
        rv = self.lib.C_DestroyObject(self.session, obj)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def digestSession(self, mecha=MechanismSHA1):
        """
        C_DigestInit/C_DigestUpdate/C_DigestKey/C_DigestFinal
        @param mecha: the digesting mechanism to be used
        @type mecha: L{Mechanism} instance or L{MechanismSHA1}
        for CKM_SHA_1
        @return: A DigestSession object
        @rtype: DigestSession
        """
        return DigestSession(self.lib, self.session, mecha)

    def digest(self, data, mecha=MechanismSHA1):
        """
        C_DigestInit/C_Digest

        @param data: the data to be digested
        @type data:  (binary) sring or list/tuple of bytes
        @param mecha: the digesting mechanism to be used
        @type mecha: L{Mechanism} instance or L{MechanismSHA1}
        for CKM_SHA_1
        @return: the computed digest
        @rtype: list of bytes

        @note: the returned value is an istance of L{ckbytelist}.
        You can easly convert it to a binary string with::
            ''.join(chr(i) for i in ckbytelistDigest)

        """
        digest = ckbytelist()
        ps = None  # must be declared here or may be deallocated too early
        m = mecha.to_native()
        data1 = ckbytelist()
        data1.reserve(len(data))
        if isinstance(data, bytes):
            for x in data:
                data1.append(byte_to_int(x))
        else:
            for c in range(len(data)):
                data1.append(data[c])
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

        @param key: a key handle, obtained calling L{findObjects}.
        @type key: integer
        @param data: the data to be signed
        @type data:  (binary) string or list/tuple of bytes
        @param mecha: the signing mechanism to be used
        @type mecha: L{Mechanism} instance or L{MechanismRSAPKCS1}
        for CKM_RSA_PKCS
        @return: the computed signature
        @rtype: list of bytes

        @note: the returned value is an instance of L{ckbytelist}.
        You can easly convert it to a binary string with::
            ''.join(chr(i) for i in ckbytelistSignature)

        """
        m = mecha.to_native()
        signature = ckbytelist()
        data1 = ckbytelist()
        data1.reserve(len(data))
        if isinstance(data, bytes):
            for x in data:
                data1.append(byte_to_int(x))
        else:
            for c in range(len(data)):
                data1.append(data[c])
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

        @param key: a key handle, obtained calling L{findObjects}.
        @type key: integer
        @param data: the data that was signed
        @type data:  (binary) string or list/tuple of bytes
        @param signature: the signature to be verified
        @type signature:  (binary) string or list/tuple of bytes
        @param mecha: the signing mechanism to be used
        @type mecha: L{Mechanism} instance or L{MechanismRSAPKCS1}
        for CKM_RSA_PKCS
        @return: True if signature is valid, False otherwise
        @rtype: bool

        """
        m = mecha.to_native()
        data1 = ckbytelist()
        data1.reserve(len(data))

        if isinstance(data, bytes):
            for x in data:
                data1.append(byte_to_int(x))
        else:
            for c in range(len(data)):
                data1.append(data[c])
        rv = self.lib.C_VerifyInit(self.session, m, key)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        rv = self.lib.C_Verify(self.session, data1, signature)
        if rv == CKR_OK:
            return True
        elif rv == CKR_SIGNATURE_INVALID:
            return False
        else:
            raise PyKCS11Error(rv)

    def encrypt(self, key, data, mecha=MechanismRSAPKCS1):
        """
        C_EncryptInit/C_Encrypt

        @param key: a key handle, obtained calling L{findObjects}.
        @type key: integer
        @param data: the data to be encrypted
        @type data:  (binary) string or list/tuple of bytes
        @param mecha: the encryption mechanism to be used
        @type mecha: L{Mechanism} instance or L{MechanismRSAPKCS1}
        for CKM_RSA_PKCS
        @return: the encrypted data
        @rtype: list of bytes

        @note: the returned value is an instance of L{ckbytelist}.
        You can easly convert it to a binary string with::
            ''.join(chr(i) for i in ckbytelistEncrypted)

        """
        encrypted = ckbytelist()
        ps = None  # must be declared here or may be deallocated too early
        m = mecha.to_native()
        data1 = ckbytelist()
        data1.reserve(len(data))
        if isinstance(data, bytes):
            for x in data:
                data1.append(byte_to_int(x))
        else:
            for c in range(len(data)):
                data1.append(data[c])
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

    def decrypt(self, key, data, mecha=MechanismRSAPKCS1):
        """
        C_DecryptInit/C_Decrypt

        @param key: a key handle, obtained calling L{findObjects}.
        @type key: integer
        @param data: the data to be decrypted
        @type data:  (binary) string or list/tuple of bytes
        @param mecha: the decrypt mechanism to be used
        @type mecha: L{Mechanism} instance or L{MechanismRSAPKCS1}
        for CKM_RSA_PKCS
        @return: the decrypted data
        @rtype: list of bytes

        @note: the returned value is an instance of L{ckbytelist}.
        You can easly convert it to a binary string with::
            ''.join(chr(i) for i in ckbytelistData)

        """
        m = mecha.to_native()
        decrypted = ckbytelist()
        data1 = ckbytelist()
        data1.reserve(len(data))
        if isinstance(data, bytes):
            for x in data:
                data1.append(byte_to_int(x))
        else:
            for c in range(len(data)):
                data1.append(data[c])
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

    def wrapKey(self, wrappingKey, key, mecha=MechanismRSAPKCS1):
        """
        C_WrapKey

        @param wrappingKey: a wrapping key handle
        @type wrappingKey: integer
        @param key: a handle of the key to be wrapped
        @type key: integer
        @param mecha: the encrypt mechanism to be used
        @type mecha: L{Mechanism} instance or L{MechanismRSAPKCS1}
        for CKM_RSA_PKCS
        @return: the wrapped key bytes
        @rtype: list of bytes

        @note: the returned value is an instance of L{ckbytelist}.
        You can easily convert it to a binary string with::
            ''.join(chr(i) for i in ckbytelistData)

        """
        m = PyKCS11.LowLevel.CK_MECHANISM()
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

        @param unwrappingKey: the unwrapping key handle
        @type unwrappingKey: integer
        @param wrappedKey: the bytes of the wrapped key
        @type wrappedKey:  (binary) string or list/tuple of bytes
        @param template: template for the unwrapped key
        @param mecha: the decrypt mechanism to be used
        @type mecha: L{Mechanism} instance or L{MechanismRSAPKCS1}
        for CKM_RSA_PKCS
        @return: the unwrapped key object
        @rtype: integer

        """
        m = mecha.to_native()
        wrapped = ckbytelist()
        data1 = ckbytelist()
        data1.reserve(len(wrappedKey))
        if isinstance(wrappedKey, bytes):
            for x in wrappedKey:
                data1.append(byte_to_int(x))
        else:
            for c in range(len(wrappedKey)):
                data1.append(wrappedKey[c])
        handle = PyKCS11.LowLevel.CK_OBJECT_HANDLE()
        attrs = self._template2ckattrlist(template)
        rv = self.lib.C_UnwrapKey(self.session, m, unwrappingKey, data1, attrs, handle)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return handle

    def isNum(self, type):
        """
        is the type a numerical value?

        @param type: PKCS#11 type like CKA_CERTIFICATE_TYPE
        @rtype: bool
        """
        if type in (CKA_CERTIFICATE_TYPE,
            CKA_CLASS,
            CKA_KEY_GEN_MECHANISM,
            CKA_KEY_TYPE,
            CKA_MODULUS_BITS,
            CKA_VALUE_BITS,
            CKA_VALUE_LEN):
            return True
        return False

    def isString(self, type):
        """
        is the type a string value?

        @param type: PKCS#11 type like CKA_LABEL
        @rtype: bool
        """
        if type in (CKA_LABEL,
            CKA_APPLICATION):
            return True
        return False

    def isBool(self, type):
        """
        is the type a boolean value?

        @param type: PKCS#11 type like CKA_ALWAYS_SENSITIVE
        @rtype: bool
        """
        if type in (CKA_ALWAYS_SENSITIVE,
            CKA_DECRYPT,
            CKA_DERIVE,
            CKA_ENCRYPT,
            CKA_EXTRACTABLE,
            CKA_HAS_RESET,
            CKA_LOCAL,
            CKA_MODIFIABLE,
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
            CKA_WRAP_WITH_TRUSTED):
            return True
        return False

    def isBin(self, type):
        """
        is the type a byte array value?

        @param type: PKCS#11 type like CKA_MODULUS
        @rtype: bool
        """
        return (not self.isBool(type)) and (not self.isString(type)) and (not self.isNum(type))

    def _template2ckattrlist(self, template):
        t = PyKCS11.LowLevel.ckattrlist(len(template))
        for x in range(len(template)):
            attr = template[x]
            if self.isNum(attr[0]):
                t[x].SetNum(attr[0], int(attr[1]))
            elif self.isString(attr[0]):
                t[x].SetString(attr[0], str(attr[1]))
            elif self.isBool(attr[0]):
                t[x].SetBool(attr[0], attr[1] == CK_TRUE)
            elif self.isBin(attr[0]):
                attrBin = attr[1]
                attrStr = attr[1]
                if isinstance(attr[1], int):
                    attrStr = str(attr[1])
                if isinstance(attr[1], bytes):
                    attrBin = ckbytelist()
                    attrBin.reserve(len(attrStr))
                    for c in range(len(attrStr)):
                        attrBin.append(byte_to_int(attrStr[c]))
                t[x].SetBin(attr[0], attrBin)
            else:
                raise PyKCS11Error(-2)
        return t

    def generateKey(self, template, mecha=MechanismAESGENERATEKEY):
        """
        generate a secret key

        @param template: template for the secret key
        @param mecha: mechanism to use
        @return: handle of the generated key
        @rtype: PyKCS11.LowLevel.CK_OBJECT_HANDLE
        """
        t = self._template2ckattrlist(template)
        ck_handle = PyKCS11.LowLevel.CK_OBJECT_HANDLE()
        m = mecha.to_native()
        rv = self.lib.C_GenerateKey(self.session, m, t, ck_handle)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return ck_handle

    def generateKeyPair(self, templatePub, templatePriv, mecha=MechanismRSAGENERATEKEYPAIR):
        """
        generate a key pair

        @param templatePub: template for the public key
        @param templatePriv:  template for the private key
        @param mecha: mechanism to use
        @return: a tuple of handles (pub, priv)
        @rtype: tuple
        """
        tPub = self._template2ckattrlist(templatePub)
        tPriv = self._template2ckattrlist(templatePriv)
        ck_pub_handle = PyKCS11.LowLevel.CK_OBJECT_HANDLE()
        ck_prv_handle = PyKCS11.LowLevel.CK_OBJECT_HANDLE()
        m = mecha.to_native()
        rv = self.lib.C_GenerateKeyPair(self.session, m, tPub, tPriv,
            ck_pub_handle, ck_prv_handle)

        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return ck_pub_handle, ck_prv_handle

    def findObjects(self, template=()):
        """
        find the objects matching the template pattern

        @param template: list of attributes tuples (attribute,value).
        The default value is () and all the objects are returned
        @type template: list
        @return: a list of object ids
        @rtype: list
        """
        t = self._template2ckattrlist(template)

        # we search for 10 objects by default. speed/memory tradeoff
        result = PyKCS11.LowLevel.ckobjlist(10)

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
                a.assign(x.value())
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

        @param obj_id: object ID returned by L{findObjects}
        @type obj_id: integer
        @param attr: list of attributes
        @type attr: list
        @param allAsBinary: return all values as binary data; default is False.
        @type allAsBinary: Boolean
        @return: a list of values corresponding to the list of attributes
        @rtype: list

        @see: L{getAttributeValue_fragmented}

        @note: if allAsBinary is True the function do not convert results to
        Python types (i.e.: CKA_TOKEN to Bool, CKA_CLASS to int, ...).
        Binary data is returned as L{ckbytelist} type, usable
        as a list containing only bytes.
        You can easly convert it to a binary string with::
            ''.join(chr(i) for i in ckbytelistVariable)

        """
        valTemplate = PyKCS11.LowLevel.ckattrlist(len(attr))
        for x in range(len(attr)):
            valTemplate[x].SetType(attr[x])
        # first call to get the attribute size and reserve the memory
        rv = self.lib.C_GetAttributeValue(self.session, obj_id, valTemplate)
        if rv == CKR_ATTRIBUTE_TYPE_INVALID \
           or rv == CKR_ATTRIBUTE_SENSITIVE:
            return self.getAttributeValue_fragmented(obj_id, attr, allAsBinary)

        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        # second call to get the attribute value
        rv = self.lib.C_GetAttributeValue(self.session, obj_id, valTemplate)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        res = []
        for x in range(len(attr)):
            if (allAsBinary):
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
                raise PyKCS11Error(-2)

        return res

    def getAttributeValue_fragmented(self, obj_id, attr, allAsBinary=False):
        """
        Same as L{getAttributeValue} except that when some attribute
        is sensitive or unknown an empty value (None) is returned.

        Note: this is achived by getting attributes one by one.

        @see: L{getAttributeValue}
        """
        # some attributes does not exists or is sensitive
        # but we don't know which ones. So try one by one
        valTemplate = PyKCS11.LowLevel.ckattrlist(1)
        res = []
        for x in range(len(attr)):
            valTemplate[0].Reset()
            valTemplate[0].SetType(attr[x])
            # first call to get the attribute size and reserve the memory
            rv = self.lib.C_GetAttributeValue(self.session, obj_id, valTemplate)
            if rv == CKR_ATTRIBUTE_TYPE_INVALID \
               or rv == CKR_ATTRIBUTE_SENSITIVE:
                # append an empty value
                res.append(None)
                continue

            if rv != CKR_OK:
                raise PyKCS11Error(rv)
            # second call to get the attribute value
            rv = self.lib.C_GetAttributeValue(self.session, obj_id, valTemplate)
            if rv != CKR_OK:
                raise PyKCS11Error(rv)

            if (allAsBinary):
                res.append(valTemplate[0].GetBin())
            elif valTemplate[0].IsNum():
                res.append(valTemplate[0].GetNum())
            elif valTemplate[0].IsBool():
                res.append(valTemplate[0].GetBool())
            elif valTemplate[0].IsString():
                res.append(valTemplate[0].GetString())
            elif valTemplate[0].IsBin():
                res.append(valTemplate[0].GetBin())
            else:
                raise PyKCS11Error(-2)

        return res

    def seedRandom(self, seed):
        """
        C_SeedRandom

        @param seed: seed material
        @type seed: iterable
        """
        low_seed = ckbytelist(len(seed))
        for c in range(len(seed)):
            low_seed.append(seed[c])
        rv = self.lib.C_SeedRandom(self.session, low_seed)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def generateRandom(self, size=16):
        """
        C_GenerateRandom

        @param size: number of random bytes to get
        @type size: integer

        @note: the returned value is an instance of L{ckbytelist}.
        You can easly convert it to a binary string with::
            ''.join(chr(i) for i in random)
        """
        low_rand = ckbytelist(size)
        rv = self.lib.C_GenerateRandom(self.session, low_rand)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return low_rand

if __name__ == "__main__":
    # sample test/debug code
    p = PyKCS11Lib()
    p.load()

    print("getInfo")
    print(p.getInfo())

    print()
    print("getSlotList")
    s = p.getSlotList()
    print("slots:", s)
    slot = s[0]
    print("using slot:", slot)

    print()
    print("getSlotInfo")
    print(p.getSlotInfo(slot))

    print()
    print("getTokenInfo")
    print(p.getTokenInfo(slot))

    print()
    print("openSession")
    se = p.openSession(slot)

    print()
    print("sessionInfo")
    print(se.getSessionInfo())

    print()
    print("seedRandom")
    try:
        se.seedRandom([1, 2, 3, 4])
    except PyKCS11Error as e:
        print(e)
    print("generateRandom")
    print(se.generateRandom())

    print()
    print("login")
    se.login(pin="0000")

    print()
    print("sessionInfo")
    print(se.getSessionInfo())

    print()
    print("findObjects")
    objs = se.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])
    print("Nb objetcs:", len(objs))
    print(objs)

    print()
    print("getAttributeValue")
    for o in objs:
        attr = se.getAttributeValue(o, [CKA_LABEL, CKA_CLASS])
        print(attr)

    print()
    print("logout")
    se.logout()

    print()
    print("closeSession")
    se.closeSession()
