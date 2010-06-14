#   Copyright (C) 2006-2008 Ludovic Rousseau (ludovic.rousseau@free.fr)
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

import PyKCS11.LowLevel
import os

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
      or x[:4] == 'CKS_':
        a = "%s=PyKCS11.LowLevel.%s" % (x, x)
        exec(a)
        if x[3:] != "_VENDOR_DEFINED":
            eval(x[:3])[eval(x)] = x  # => CKM[CKM_RSA_PKCS] = 'CKM_RSA_PKCS'
            eval(x[:3])[x] = eval(x)  # => CKM['CKM_RSA_PKCS'] = CKM_RSA_PKCS

# special CKR[] values
CKR[-2] = "Unkown PKCS#11 type"
CKR[-1] = "Load"


class CK_SLOT_INFO(object):
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

    def flags2text(self):
        """
        parse the L{self.flags} field and create a list of "CKF_*" strings
        corresponding to bits set in flags

        @return: a list of strings
        @rtype: list
        """
        r = []
        for v in CK_SLOT_INFO.flags_dict.keys():
            if self.flags & v:
                r.append(CK_SLOT_INFO.flags_dict[v])
        return r


class CK_INFO(object):
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


class CK_SESSION_INFO(object):
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

    def flags2text(self):
        """
        parse the L{self.flags} field and create a list of "CKF_*" strings
        corresponding to bits set in flags

        @return: a list of strings
        @rtype: list
        """
        r = []
        for v in CK_SESSION_INFO.flags_dict.keys():
            if self.flags & v:
                r.append(CK_SESSION_INFO.flags_dict[v])
        return r

    def state2text(self):
        """
        parse the L{self.state} field and return a "CKS_*" string
        corresponding to the state

        @return: a string
        @rtype: string
        """
        return CKS[self.state]


class CK_TOKEN_INFO(object):
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

    def flags2text(self):
        """
        parse the L{flags} field and create a list of "CKF_*" strings
        corresponding to bits set in flags

        @return: a list of strings
        @rtype: list
        """
        r = []
        for v in CK_TOKEN_INFO.flags_dict.keys():
            if self.flags & v:
                r.append(CK_TOKEN_INFO.flags_dict[v])
        return r


class CK_MECHANISM_INFO(object):
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

    def flags2text(self):
        """
        parse the L{self.flags} field and create a list of "CKF_*" strings
        corresponding to bits set in flags

        @return: a list of strings
        @rtype: list
        """
        r = []
        for v in CK_MECHANISM_INFO.flags_dict.keys():
            if self.flags & v:
                r.append(CK_MECHANISM_INFO.flags_dict[v])
        return r


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
        if pkcs11dll_filename == None:
            pkcs11dll_filename = os.getenv("PYKCS11LIB")
            if pkcs11dll_filename == None:
                raise PyKCS11Error(-1, "No PKCS11 library specified (set PYKCS11LIB env variable)")
        rv = self.lib.Load(pkcs11dll_filename, 1)
        if rv == 0:
            raise PyKCS11Error(-1, pkcs11dll_filename)

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
        for x in xrange(len(slotList)):
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
        CKU_SO = PyKCS11.LowLevel.CKU_SO
        CKU_USER = PyKCS11.LowLevel.CKU_USER

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
        @param flags: 0 (default), CKF_RW_SESSION for RW session
        @type flags: integer
        @return: a L{Session} object
        """
        se = PyKCS11.LowLevel.CK_SESSION_HANDLE()
        flags |= CKF_SERIAL_SESSION
        rv = self.lib.C_OpenSession(slot, flags, se)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        s = Session()
        s.lib = self.lib
        s.slot = slot
        s.session = se
        return s

    def getMechanismList(self, slot):
        """
        C_GetMechanismList

        @return: the list of available mechanisms for a slot
        @rtype: list
        """
        mechanismList = PyKCS11.LowLevel.ckintlist()
        rv = self.lib.C_GetMechanismList(slot, mechanismList)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

        m = []
        for x in xrange(len(mechanismList)):
            m.append(CKM[mechanismList[x]])
        return m

    def getMechanismInfo(self, slot, type):
        """
        C_GetMechanismInfo

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

    def __init__(self, mechanism, param):
        """
        @param mechanism: the mechanism to be used
        @type mechanism: integer, any CKM_* value
        @param param: data to be used as crypto operation parameter
        (i.e. the IV for some agorithms)
        @type param: string or list/tuple of bytes

        @see: L{Session.decrypt}, L{Session.sign}
        """
        self.mechanism = mechanism
        self.param = param

MechanismRSAPKCS1 = Mechanism(CKM_RSA_PKCS, None)


class Session(object):
    """ Manage L{PyKCS11Lib.openSession} objects """

    def closeSession(self):
        """
        C_CloseSession
        """
        rv = self.lib.C_CloseSession(self.session)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def closeAllSession(self):
        """
        C_CloseAllSession
        """
        rv = self.lib.C_CloseAllSession(self.slot)
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

        @param pin: the user's PIN
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

    def initToken(self, pin, label):
        """
        C_InitToken
        """
        rv = self.lib.C_InitToken(self.session, pin, label)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def initPin(self, new_pin):
        """
        C_InitPIN
        """
        rv = self.lib.C_InitPIN(self.session, new_pin)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def setPin(self, old_pin, new_pin):
        """
        C_SetPIN
        """
        rv = self.lib.C_SetPIN(self.session, old_pin, new_pin)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def sign(self, key, data, mecha=MechanismRSAPKCS1):
        """
        C_SignInit/C_Sign

        @param key: a key handle, obtained calling L{findObjects}.
        @type key: integer
        @param data: the data to be signed
        @type data:  (binary) sring or list/tuple of bytes
        @param mecha: the signing mechanism to be used
        @type mecha: L{Mechanism} instance or L{MechanismRSAPKCS1}
        for CKM_RSA_PKCS
        @return: the computed signature
        @rtype: list of bytes

        @note: the returned value is an istance of L{LowLevel.ckbytelist}.
        You can easly convert it to a binary string with::
            ''.join(chr(i) for i in ckbytelistSignature)

        """
        m = PyKCS11.LowLevel.CK_MECHANISM()
        signature = PyKCS11.LowLevel.ckbytelist()
        ba = None  # must be declared here or may be deallocated too early
        m.mechanism = mecha.mechanism
        if (mecha.param):
            ba = PyKCS11.LowLevel.byteArray(len(mecha.param))
            if type(mecha.param) is type(''):
                for c in xrange(len(mecha.param)):
                    ba[c] = ord(mecha.param[c])
            else:
                for c in xrange(len(mecha.param)):
                    ba[c] = mecha.param[c]
            # with cast() the ba object continue to own internal pointer
            # (avoids a leak).
            # pParameter is an opaque pointer, never garbage collected.
            m.pParameter = ba.cast()
            m.ulParameterLen = len(mecha.param)
        data1 = PyKCS11.LowLevel.ckbytelist()
        data1.reserve(len(data))
        if type(data) is type(''):
            for x in data:
                data1.append(ord(x))
        else:
            for c in xrange(len(data)):
                data1.append(data[c])
        rv = self.lib.C_SignInit(self.session, m, key)
        if (rv != 0):
            raise PyKCS11Error(rv)
        #first call get signature size
        rv = self.lib.C_Sign(self.session, data1, signature)
        if (rv != 0):
            raise PyKCS11Error(rv)
        #second call get actual signature data
        rv = self.lib.C_Sign(self.session, data1, signature)
        if (rv != 0):
            raise PyKCS11Error(rv)
        return signature

    def decrypt(self, key, data, mecha=MechanismRSAPKCS1):
        """
        C_DecryptInit/C_Decrypt

        @param key: a key handle, obtained calling L{findObjects}.
        @type key: integer
        @param data: the data to be decrypted
        @type data:  (binary) sring or list/tuple of bytes
        @param mecha: the decrypt mechanism to be used
        @type mecha: L{Mechanism} instance or L{MechanismRSAPKCS1}
        for CKM_RSA_PKCS
        @return: the decrypted data
        @rtype: list of bytes

        @note: the returned value is an istance of L{LowLevel.ckbytelist}.
        You can easly convert it to a binary string with::
            ''.join(chr(i) for i in ckbytelistData)

        """
        m = PyKCS11.LowLevel.CK_MECHANISM()
        decrypted = PyKCS11.LowLevel.ckbytelist()
        ba = None  # must be declared here or may be deallocated too early
        m.mechanism = mecha.mechanism
        if (mecha.param):
            ba = PyKCS11.LowLevel.byteArray(len(mecha.param))
            if type(mecha.param) is type(''):
                for c in xrange(len(mecha.param)):
                    ba[c] = ord(mecha.param[c])
            else:
                for c in xrange(len(mecha.param)):
                    ba[c] = mecha.param[c]
            # with cast() the ba object continue to own internal pointer
            # (avoids a leak).
            # pParameter is an opaque pointer, never garbage collected.
            m.pParameter = ba.cast()
            m.ulParameterLen = len(mecha.param)
        data1 = PyKCS11.LowLevel.ckbytelist()
        data1.reserve(len(data))
        if type(data) is type(''):
            for x in data:
                data1.append(ord(x))
        else:
            for c in xrange(len(data)):
                data1.append(data[c])
        rv = self.lib.C_DecryptInit(self.session, m, key)
        if (rv != 0):
            raise PyKCS11Error(rv)
        #first call get decrypted size
        rv = self.lib.C_Decrypt(self.session, data1, decrypted)
        if (rv != 0):
            raise PyKCS11Error(rv)
        #second call get actual decrypted data
        rv = self.lib.C_Decrypt(self.session, data1, decrypted)
        if (rv != 0):
            raise PyKCS11Error(rv)
        return decrypted

    def isNum(self, type):
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
        if type in (CKA_LABEL,
            CKA_APPLICATION):
            return True
        return False

    def isBool(self, type):
        if type in (CKA_ALWAYS_SENSITIVE,
            CKA_DECRYPT,
            CKA_ENCRYPT,
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
            CKA_WRAP):
            return True
        return False

    def isBin(self, type):
        return (not self.isBool(type)) and (not self.isString(type)) and (not self.isNum(type))

    def findObjects(self, template=()):
        """
        find the objects matching the template pattern

        @param template: list of attributes tuples (attribute,value).
        The default value is () and all the objects are returned
        @type template: list
        @return: a list of object ids
        @rtype: list
        """
        t = PyKCS11.LowLevel.ckattrlist(len(template))
        for x in xrange(len(template)):
            attr = template[x]
            if self.isNum(attr[0]):
                t[x].SetNum(attr[0], attr[1])
            elif self.isString(attr[0]):
                t[x].SetString(attr[0], attr[1])
            elif self.isBool(attr[0]):
                t[x].SetBool(attr[0], attr[1])
            elif self.isBin(attr[0]):
                t[x].SetBin(attr[0], attr[1])
            else:
                raise PyKCS11Error(-2)

        # we search for 10 objects by default. speed/memory tradeoff
        result = PyKCS11.LowLevel.ckobjlist(10)

        self.lib.C_FindObjectsInit(self.session, t)

        res = []
        while True:
            self.lib.C_FindObjects(self.session, result)
            for x in result:
                # make a copy of the handle: the original value get
                # corrupted (!!)
                a = PyKCS11.LowLevel.CK_OBJECT_HANDLE()
                a.assign(x.value())
                res.append(a)
            if len(result) == 0:
                break

        self.lib.C_FindObjectsFinal(self.session)
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
        Binary data is returned as L{LowLevel.ckbytelist} type, usable
        as a list containing only bytes.
        You can easly convert it to a binary string with::
            ''.join(chr(i) for i in ckbytelistVariable)

        """
        valTemplate = PyKCS11.LowLevel.ckattrlist(len(attr))
        for x in xrange(len(attr)):
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
        for x in xrange(len(attr)):
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
        is sensitive or unknown an empty value (None) is retruned.

        Note: this is achived getting attributes one by one.

        @see: L{getAttributeValue}
        """
        # some attributes does not exists or is sensitive
        # but we don't know which ones. So try one by one
        valTemplate = PyKCS11.LowLevel.ckattrlist(1)
        res = []
        for x in xrange(len(attr)):
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
        low_seed = PyKCS11.LowLevel.ckbytelist(len(seed))
        for c in xrange(len(seed)):
            low_seed.append(seed[c])
        rv = self.lib.C_SeedRandom(self.session, low_seed)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)

    def generateRandom(self, size=16):
        """
        C_GenerateRandom

        @param size: number of random bytes to get
        @type size: integer

        @note: the returned value is an istance of L{LowLevel.ckbytelist}.
        You can easly convert it to a binary string with::
            ''.join(chr(i) for i in ckbytelistSignature)
        """
        low_rand = PyKCS11.LowLevel.ckbytelist(size)
        rv = self.lib.C_GenerateRandom(self.session, low_rand)
        if rv != CKR_OK:
            raise PyKCS11Error(rv)
        return low_rand

if __name__ == "__main__":
    # sample test/debug code
    p = PyKCS11Lib()
    p.load()

    print "getInfo"
    i = p.getInfo()
    print "cryptokiVersion: %d.%d" % i.cryptokiVersion
    print "manufacturerID:", i.manufacturerID
    print "flags:", i.flags
    print "libraryDescription:", i.libraryDescription
    print "libraryVersion: %d.%d" % i.libraryVersion

    print
    print "getSlotList"
    s = p.getSlotList()
    print "slots:", s
    slot = s[1]
    print "using slot:", slot

    print
    print "getSlotInfo"
    i = p.getSlotInfo(slot)
    print "slotDescription:", i.slotDescription.strip()
    print "manufacturerID:", i.manufacturerID
    print "flags:", i.flags
    print "flags:", i.flags2text()
    print "hardwareVersion:", i.hardwareVersion
    print "firmwareVersion:", i.firmwareVersion

    print
    print "getTokenInfo"
    t = p.getTokenInfo(slot)
    print "label:", t.label
    print "manufacturerID:", t.manufacturerID
    print "model:", t.model
    print "serialNumber:", t.serialNumber
    print "flags:", t.flags
    print "flags:", t.flags2text()
    print "ulMaxSessionCount:", t.ulMaxSessionCount
    print "ulSessionCount:", t.ulSessionCount
    print "ulMaxRwSessionCount:", t.ulMaxRwSessionCount
    print "ulRwSessionCount:", t.ulRwSessionCount
    print "ulMaxPinLen:", t.ulMaxPinLen
    print "ulMinPinLen:", t.ulMinPinLen
    print "ulTotalPublicMemory:", t.ulTotalPublicMemory
    print "ulFreePublicMemory:", t.ulFreePublicMemory
    print "ulTotalPrivateMemory:", t.ulTotalPrivateMemory
    print "ulFreePrivateMemory:", t.ulFreePrivateMemory
    print "hardwareVersion: %d.%d" % t.hardwareVersion
    print "firmwareVersion: %d.%d" % t.firmwareVersion
    print "utcTime:", t.utcTime

    print
    print "openSession"
    se = p.openSession(slot)

    print
    print "sessionInfo"
    si = se.getSessionInfo()
    print "slotID:", si.slotID
    print "state:", si.state
    print "state:", si.state2text()
    print "flags:", si.flags
    print "flags:", si.flags2text()
    print "ulDeviceError:", si.ulDeviceError

    print
    print "seedRandom"
    try:
        se.seedRandom([1, 2, 3, 4])
    except PyKCS11Error, e:
        print e
    print "generateRandom"
    rand = se.generateRandom()
    print " ".join("%02X" % i for i in rand)

    print
    print "login"
    se.login(pin="12345678")

    print
    print "sessionInfo"
    si = se.getSessionInfo()
    print "slotID:", si.slotID
    print "state:", si.state
    print "state:", si.state2text()
    print "flags:", si.flags
    print "flags:", si.flags2text()
    print "ulDeviceError:", si.ulDeviceError

    print
    print "findObjects"
    objs = se.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])
    print objs

    print
    print "getAttributeValue"
    for o in objs:
        attr = se.getAttributeValue(o, [CKA_LABEL, CKA_CLASS])
        print attr

    print
    print "logout"
    se.logout()

    print
    print "closeSession"
    se.closeSession()
