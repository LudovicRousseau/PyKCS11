# This file was created automatically by SWIG.
# Don't modify this file, modify the SWIG interface instead.
# This file is compatible with both classic and new-style classes.

import _PyKCS11

def _swig_setattr(self,class_type,name,value):
    if (name == "this"):
        if isinstance(value, class_type):
            self.__dict__[name] = value.this
            if hasattr(value,"thisown"): self.__dict__["thisown"] = value.thisown
            del value.thisown
            return
    method = class_type.__swig_setmethods__.get(name,None)
    if method: return method(self,value)
    self.__dict__[name] = value

def _swig_getattr(self,class_type,name):
    method = class_type.__swig_getmethods__.get(name,None)
    if method: return method(self)
    raise AttributeError,name

import types
try:
    _object = types.ObjectType
    _newclass = 1
except AttributeError:
    class _object : pass
    _newclass = 0
del types



cdata = _PyKCS11.cdata

memmove = _PyKCS11.memmove
class ckintlist(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, ckintlist, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, ckintlist, name)
    def __repr__(self):
        return "<C vector<(int)> instance at %s>" % (self.this,)
    def empty(*args): return _PyKCS11.ckintlist_empty(*args)
    def size(*args): return _PyKCS11.ckintlist_size(*args)
    def clear(*args): return _PyKCS11.ckintlist_clear(*args)
    def swap(*args): return _PyKCS11.ckintlist_swap(*args)
    def pop_back(*args): return _PyKCS11.ckintlist_pop_back(*args)
    def __init__(self, *args):
        _swig_setattr(self, ckintlist, 'this', _PyKCS11.new_ckintlist(*args))
        _swig_setattr(self, ckintlist, 'thisown', 1)
    def push_back(*args): return _PyKCS11.ckintlist_push_back(*args)
    def front(*args): return _PyKCS11.ckintlist_front(*args)
    def back(*args): return _PyKCS11.ckintlist_back(*args)
    def assign(*args): return _PyKCS11.ckintlist_assign(*args)
    def resize(*args): return _PyKCS11.ckintlist_resize(*args)
    def reserve(*args): return _PyKCS11.ckintlist_reserve(*args)
    def capacity(*args): return _PyKCS11.ckintlist_capacity(*args)
    def __nonzero__(*args): return _PyKCS11.ckintlist___nonzero__(*args)
    def __len__(*args): return _PyKCS11.ckintlist___len__(*args)
    def pop(*args): return _PyKCS11.ckintlist_pop(*args)
    def __getslice__(*args): return _PyKCS11.ckintlist___getslice__(*args)
    def __setslice__(*args): return _PyKCS11.ckintlist___setslice__(*args)
    def __delslice__(*args): return _PyKCS11.ckintlist___delslice__(*args)
    def __delitem__(*args): return _PyKCS11.ckintlist___delitem__(*args)
    def __getitem__(*args): return _PyKCS11.ckintlist___getitem__(*args)
    def __setitem__(*args): return _PyKCS11.ckintlist___setitem__(*args)
    def append(*args): return _PyKCS11.ckintlist_append(*args)
    def __del__(self, destroy=_PyKCS11.delete_ckintlist):
        try:
            if self.thisown: destroy(self)
        except: pass

class ckintlistPtr(ckintlist):
    def __init__(self, this):
        _swig_setattr(self, ckintlist, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, ckintlist, 'thisown', 0)
        _swig_setattr(self, ckintlist,self.__class__,ckintlist)
_PyKCS11.ckintlist_swigregister(ckintlistPtr)

class ckbytelist(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, ckbytelist, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, ckbytelist, name)
    def __repr__(self):
        return "<C vector<(unsigned char)> instance at %s>" % (self.this,)
    def empty(*args): return _PyKCS11.ckbytelist_empty(*args)
    def size(*args): return _PyKCS11.ckbytelist_size(*args)
    def clear(*args): return _PyKCS11.ckbytelist_clear(*args)
    def swap(*args): return _PyKCS11.ckbytelist_swap(*args)
    def pop_back(*args): return _PyKCS11.ckbytelist_pop_back(*args)
    def __init__(self, *args):
        _swig_setattr(self, ckbytelist, 'this', _PyKCS11.new_ckbytelist(*args))
        _swig_setattr(self, ckbytelist, 'thisown', 1)
    def push_back(*args): return _PyKCS11.ckbytelist_push_back(*args)
    def front(*args): return _PyKCS11.ckbytelist_front(*args)
    def back(*args): return _PyKCS11.ckbytelist_back(*args)
    def assign(*args): return _PyKCS11.ckbytelist_assign(*args)
    def resize(*args): return _PyKCS11.ckbytelist_resize(*args)
    def reserve(*args): return _PyKCS11.ckbytelist_reserve(*args)
    def capacity(*args): return _PyKCS11.ckbytelist_capacity(*args)
    def __nonzero__(*args): return _PyKCS11.ckbytelist___nonzero__(*args)
    def __len__(*args): return _PyKCS11.ckbytelist___len__(*args)
    def pop(*args): return _PyKCS11.ckbytelist_pop(*args)
    def __getslice__(*args): return _PyKCS11.ckbytelist___getslice__(*args)
    def __setslice__(*args): return _PyKCS11.ckbytelist___setslice__(*args)
    def __delslice__(*args): return _PyKCS11.ckbytelist___delslice__(*args)
    def __delitem__(*args): return _PyKCS11.ckbytelist___delitem__(*args)
    def __getitem__(*args): return _PyKCS11.ckbytelist___getitem__(*args)
    def __setitem__(*args): return _PyKCS11.ckbytelist___setitem__(*args)
    def append(*args): return _PyKCS11.ckbytelist_append(*args)
    def __del__(self, destroy=_PyKCS11.delete_ckbytelist):
        try:
            if self.thisown: destroy(self)
        except: pass

class ckbytelistPtr(ckbytelist):
    def __init__(self, this):
        _swig_setattr(self, ckbytelist, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, ckbytelist, 'thisown', 0)
        _swig_setattr(self, ckbytelist,self.__class__,ckbytelist)
_PyKCS11.ckbytelist_swigregister(ckbytelistPtr)

class ckattrlist(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, ckattrlist, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, ckattrlist, name)
    def __repr__(self):
        return "<C vector<(CK_ATTRIBUTE_SMART)> instance at %s>" % (self.this,)
    def empty(*args): return _PyKCS11.ckattrlist_empty(*args)
    def size(*args): return _PyKCS11.ckattrlist_size(*args)
    def clear(*args): return _PyKCS11.ckattrlist_clear(*args)
    def swap(*args): return _PyKCS11.ckattrlist_swap(*args)
    def pop_back(*args): return _PyKCS11.ckattrlist_pop_back(*args)
    def __init__(self, *args):
        _swig_setattr(self, ckattrlist, 'this', _PyKCS11.new_ckattrlist(*args))
        _swig_setattr(self, ckattrlist, 'thisown', 1)
    def push_back(*args): return _PyKCS11.ckattrlist_push_back(*args)
    def front(*args): return _PyKCS11.ckattrlist_front(*args)
    def back(*args): return _PyKCS11.ckattrlist_back(*args)
    def assign(*args): return _PyKCS11.ckattrlist_assign(*args)
    def resize(*args): return _PyKCS11.ckattrlist_resize(*args)
    def reserve(*args): return _PyKCS11.ckattrlist_reserve(*args)
    def capacity(*args): return _PyKCS11.ckattrlist_capacity(*args)
    def __nonzero__(*args): return _PyKCS11.ckattrlist___nonzero__(*args)
    def __len__(*args): return _PyKCS11.ckattrlist___len__(*args)
    def pop(*args): return _PyKCS11.ckattrlist_pop(*args)
    def __getslice__(*args): return _PyKCS11.ckattrlist___getslice__(*args)
    def __setslice__(*args): return _PyKCS11.ckattrlist___setslice__(*args)
    def __delslice__(*args): return _PyKCS11.ckattrlist___delslice__(*args)
    def __delitem__(*args): return _PyKCS11.ckattrlist___delitem__(*args)
    def __getitem__(*args): return _PyKCS11.ckattrlist___getitem__(*args)
    def __setitem__(*args): return _PyKCS11.ckattrlist___setitem__(*args)
    def append(*args): return _PyKCS11.ckattrlist_append(*args)
    def __del__(self, destroy=_PyKCS11.delete_ckattrlist):
        try:
            if self.thisown: destroy(self)
        except: pass

class ckattrlistPtr(ckattrlist):
    def __init__(self, this):
        _swig_setattr(self, ckattrlist, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, ckattrlist, 'thisown', 0)
        _swig_setattr(self, ckattrlist,self.__class__,ckattrlist)
_PyKCS11.ckattrlist_swigregister(ckattrlistPtr)

class CK_SESSION_HANDLE(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, CK_SESSION_HANDLE, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, CK_SESSION_HANDLE, name)
    def __repr__(self):
        return "<C CK_SESSION_HANDLE instance at %s>" % (self.this,)
    def __init__(self, *args):
        _swig_setattr(self, CK_SESSION_HANDLE, 'this', _PyKCS11.new_CK_SESSION_HANDLE(*args))
        _swig_setattr(self, CK_SESSION_HANDLE, 'thisown', 1)
    def __del__(self, destroy=_PyKCS11.delete_CK_SESSION_HANDLE):
        try:
            if self.thisown: destroy(self)
        except: pass
    def assign(*args): return _PyKCS11.CK_SESSION_HANDLE_assign(*args)
    def value(*args): return _PyKCS11.CK_SESSION_HANDLE_value(*args)
    def cast(*args): return _PyKCS11.CK_SESSION_HANDLE_cast(*args)
    __swig_getmethods__["frompointer"] = lambda x: _PyKCS11.CK_SESSION_HANDLE_frompointer
    if _newclass:frompointer = staticmethod(_PyKCS11.CK_SESSION_HANDLE_frompointer)

class CK_SESSION_HANDLEPtr(CK_SESSION_HANDLE):
    def __init__(self, this):
        _swig_setattr(self, CK_SESSION_HANDLE, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, CK_SESSION_HANDLE, 'thisown', 0)
        _swig_setattr(self, CK_SESSION_HANDLE,self.__class__,CK_SESSION_HANDLE)
_PyKCS11.CK_SESSION_HANDLE_swigregister(CK_SESSION_HANDLEPtr)

CK_SESSION_HANDLE_frompointer = _PyKCS11.CK_SESSION_HANDLE_frompointer

class CK_VERSION(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, CK_VERSION, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, CK_VERSION, name)
    def __repr__(self):
        return "<C CK_VERSION instance at %s>" % (self.this,)
    __swig_getmethods__["major"] = _PyKCS11.CK_VERSION_major_get
    if _newclass:major = property(_PyKCS11.CK_VERSION_major_get)
    __swig_getmethods__["minor"] = _PyKCS11.CK_VERSION_minor_get
    if _newclass:minor = property(_PyKCS11.CK_VERSION_minor_get)
    def __init__(self, *args):
        _swig_setattr(self, CK_VERSION, 'this', _PyKCS11.new_CK_VERSION(*args))
        _swig_setattr(self, CK_VERSION, 'thisown', 1)
    def __del__(self, destroy=_PyKCS11.delete_CK_VERSION):
        try:
            if self.thisown: destroy(self)
        except: pass

class CK_VERSIONPtr(CK_VERSION):
    def __init__(self, this):
        _swig_setattr(self, CK_VERSION, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, CK_VERSION, 'thisown', 0)
        _swig_setattr(self, CK_VERSION,self.__class__,CK_VERSION)
_PyKCS11.CK_VERSION_swigregister(CK_VERSIONPtr)

class CK_INFO(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, CK_INFO, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, CK_INFO, name)
    def __repr__(self):
        return "<C CK_INFO instance at %s>" % (self.this,)
    __swig_getmethods__["cryptokiVersion"] = _PyKCS11.CK_INFO_cryptokiVersion_get
    if _newclass:cryptokiVersion = property(_PyKCS11.CK_INFO_cryptokiVersion_get)
    __swig_getmethods__["manufacturerID"] = _PyKCS11.CK_INFO_manufacturerID_get
    if _newclass:manufacturerID = property(_PyKCS11.CK_INFO_manufacturerID_get)
    __swig_getmethods__["flags"] = _PyKCS11.CK_INFO_flags_get
    if _newclass:flags = property(_PyKCS11.CK_INFO_flags_get)
    __swig_getmethods__["libraryDescription"] = _PyKCS11.CK_INFO_libraryDescription_get
    if _newclass:libraryDescription = property(_PyKCS11.CK_INFO_libraryDescription_get)
    __swig_getmethods__["libraryVersion"] = _PyKCS11.CK_INFO_libraryVersion_get
    if _newclass:libraryVersion = property(_PyKCS11.CK_INFO_libraryVersion_get)
    def GetManufacturerID(*args): return _PyKCS11.CK_INFO_GetManufacturerID(*args)
    def GetLibraryDescription(*args): return _PyKCS11.CK_INFO_GetLibraryDescription(*args)
    def GetLibraryVersion(*args): return _PyKCS11.CK_INFO_GetLibraryVersion(*args)
    def __init__(self, *args):
        _swig_setattr(self, CK_INFO, 'this', _PyKCS11.new_CK_INFO(*args))
        _swig_setattr(self, CK_INFO, 'thisown', 1)
    def __del__(self, destroy=_PyKCS11.delete_CK_INFO):
        try:
            if self.thisown: destroy(self)
        except: pass

class CK_INFOPtr(CK_INFO):
    def __init__(self, this):
        _swig_setattr(self, CK_INFO, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, CK_INFO, 'thisown', 0)
        _swig_setattr(self, CK_INFO,self.__class__,CK_INFO)
_PyKCS11.CK_INFO_swigregister(CK_INFOPtr)

class CK_SLOT_INFO(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, CK_SLOT_INFO, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, CK_SLOT_INFO, name)
    def __repr__(self):
        return "<C CK_SLOT_INFO instance at %s>" % (self.this,)
    __swig_getmethods__["flags"] = _PyKCS11.CK_SLOT_INFO_flags_get
    if _newclass:flags = property(_PyKCS11.CK_SLOT_INFO_flags_get)
    __swig_getmethods__["hardwareVersion"] = _PyKCS11.CK_SLOT_INFO_hardwareVersion_get
    if _newclass:hardwareVersion = property(_PyKCS11.CK_SLOT_INFO_hardwareVersion_get)
    __swig_getmethods__["firmwareVersion"] = _PyKCS11.CK_SLOT_INFO_firmwareVersion_get
    if _newclass:firmwareVersion = property(_PyKCS11.CK_SLOT_INFO_firmwareVersion_get)
    def GetManufacturerID(*args): return _PyKCS11.CK_SLOT_INFO_GetManufacturerID(*args)
    def GetSlotDescription(*args): return _PyKCS11.CK_SLOT_INFO_GetSlotDescription(*args)
    def GetHardwareVersion(*args): return _PyKCS11.CK_SLOT_INFO_GetHardwareVersion(*args)
    def GetFirmwareVersion(*args): return _PyKCS11.CK_SLOT_INFO_GetFirmwareVersion(*args)
    def __init__(self, *args):
        _swig_setattr(self, CK_SLOT_INFO, 'this', _PyKCS11.new_CK_SLOT_INFO(*args))
        _swig_setattr(self, CK_SLOT_INFO, 'thisown', 1)
    def __del__(self, destroy=_PyKCS11.delete_CK_SLOT_INFO):
        try:
            if self.thisown: destroy(self)
        except: pass

class CK_SLOT_INFOPtr(CK_SLOT_INFO):
    def __init__(self, this):
        _swig_setattr(self, CK_SLOT_INFO, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, CK_SLOT_INFO, 'thisown', 0)
        _swig_setattr(self, CK_SLOT_INFO,self.__class__,CK_SLOT_INFO)
_PyKCS11.CK_SLOT_INFO_swigregister(CK_SLOT_INFOPtr)

class CK_TOKEN_INFO(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, CK_TOKEN_INFO, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, CK_TOKEN_INFO, name)
    def __repr__(self):
        return "<C CK_TOKEN_INFO instance at %s>" % (self.this,)
    __swig_getmethods__["flags"] = _PyKCS11.CK_TOKEN_INFO_flags_get
    if _newclass:flags = property(_PyKCS11.CK_TOKEN_INFO_flags_get)
    __swig_getmethods__["ulMaxSessionCount"] = _PyKCS11.CK_TOKEN_INFO_ulMaxSessionCount_get
    if _newclass:ulMaxSessionCount = property(_PyKCS11.CK_TOKEN_INFO_ulMaxSessionCount_get)
    __swig_getmethods__["ulSessionCount"] = _PyKCS11.CK_TOKEN_INFO_ulSessionCount_get
    if _newclass:ulSessionCount = property(_PyKCS11.CK_TOKEN_INFO_ulSessionCount_get)
    __swig_getmethods__["ulMaxRwSessionCount"] = _PyKCS11.CK_TOKEN_INFO_ulMaxRwSessionCount_get
    if _newclass:ulMaxRwSessionCount = property(_PyKCS11.CK_TOKEN_INFO_ulMaxRwSessionCount_get)
    __swig_getmethods__["ulRwSessionCount"] = _PyKCS11.CK_TOKEN_INFO_ulRwSessionCount_get
    if _newclass:ulRwSessionCount = property(_PyKCS11.CK_TOKEN_INFO_ulRwSessionCount_get)
    __swig_getmethods__["ulMaxPinLen"] = _PyKCS11.CK_TOKEN_INFO_ulMaxPinLen_get
    if _newclass:ulMaxPinLen = property(_PyKCS11.CK_TOKEN_INFO_ulMaxPinLen_get)
    __swig_getmethods__["ulMinPinLen"] = _PyKCS11.CK_TOKEN_INFO_ulMinPinLen_get
    if _newclass:ulMinPinLen = property(_PyKCS11.CK_TOKEN_INFO_ulMinPinLen_get)
    __swig_getmethods__["ulTotalPublicMemory"] = _PyKCS11.CK_TOKEN_INFO_ulTotalPublicMemory_get
    if _newclass:ulTotalPublicMemory = property(_PyKCS11.CK_TOKEN_INFO_ulTotalPublicMemory_get)
    __swig_getmethods__["ulFreePublicMemory"] = _PyKCS11.CK_TOKEN_INFO_ulFreePublicMemory_get
    if _newclass:ulFreePublicMemory = property(_PyKCS11.CK_TOKEN_INFO_ulFreePublicMemory_get)
    __swig_getmethods__["ulTotalPrivateMemory"] = _PyKCS11.CK_TOKEN_INFO_ulTotalPrivateMemory_get
    if _newclass:ulTotalPrivateMemory = property(_PyKCS11.CK_TOKEN_INFO_ulTotalPrivateMemory_get)
    __swig_getmethods__["ulFreePrivateMemory"] = _PyKCS11.CK_TOKEN_INFO_ulFreePrivateMemory_get
    if _newclass:ulFreePrivateMemory = property(_PyKCS11.CK_TOKEN_INFO_ulFreePrivateMemory_get)
    __swig_getmethods__["hardwareVersion"] = _PyKCS11.CK_TOKEN_INFO_hardwareVersion_get
    if _newclass:hardwareVersion = property(_PyKCS11.CK_TOKEN_INFO_hardwareVersion_get)
    __swig_getmethods__["firmwareVersion"] = _PyKCS11.CK_TOKEN_INFO_firmwareVersion_get
    if _newclass:firmwareVersion = property(_PyKCS11.CK_TOKEN_INFO_firmwareVersion_get)
    def GetLabel(*args): return _PyKCS11.CK_TOKEN_INFO_GetLabel(*args)
    def GetManufacturerID(*args): return _PyKCS11.CK_TOKEN_INFO_GetManufacturerID(*args)
    def GetModel(*args): return _PyKCS11.CK_TOKEN_INFO_GetModel(*args)
    def GetSerialNumber(*args): return _PyKCS11.CK_TOKEN_INFO_GetSerialNumber(*args)
    def GetFirmwareVersion(*args): return _PyKCS11.CK_TOKEN_INFO_GetFirmwareVersion(*args)
    def __init__(self, *args):
        _swig_setattr(self, CK_TOKEN_INFO, 'this', _PyKCS11.new_CK_TOKEN_INFO(*args))
        _swig_setattr(self, CK_TOKEN_INFO, 'thisown', 1)
    def __del__(self, destroy=_PyKCS11.delete_CK_TOKEN_INFO):
        try:
            if self.thisown: destroy(self)
        except: pass

class CK_TOKEN_INFOPtr(CK_TOKEN_INFO):
    def __init__(self, this):
        _swig_setattr(self, CK_TOKEN_INFO, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, CK_TOKEN_INFO, 'thisown', 0)
        _swig_setattr(self, CK_TOKEN_INFO,self.__class__,CK_TOKEN_INFO)
_PyKCS11.CK_TOKEN_INFO_swigregister(CK_TOKEN_INFOPtr)

class CK_SESSION_INFO(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, CK_SESSION_INFO, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, CK_SESSION_INFO, name)
    def __repr__(self):
        return "<C CK_SESSION_INFO instance at %s>" % (self.this,)
    __swig_getmethods__["slotID"] = _PyKCS11.CK_SESSION_INFO_slotID_get
    if _newclass:slotID = property(_PyKCS11.CK_SESSION_INFO_slotID_get)
    __swig_getmethods__["state"] = _PyKCS11.CK_SESSION_INFO_state_get
    if _newclass:state = property(_PyKCS11.CK_SESSION_INFO_state_get)
    __swig_getmethods__["flags"] = _PyKCS11.CK_SESSION_INFO_flags_get
    if _newclass:flags = property(_PyKCS11.CK_SESSION_INFO_flags_get)
    __swig_getmethods__["ulDeviceError"] = _PyKCS11.CK_SESSION_INFO_ulDeviceError_get
    if _newclass:ulDeviceError = property(_PyKCS11.CK_SESSION_INFO_ulDeviceError_get)
    def __init__(self, *args):
        _swig_setattr(self, CK_SESSION_INFO, 'this', _PyKCS11.new_CK_SESSION_INFO(*args))
        _swig_setattr(self, CK_SESSION_INFO, 'thisown', 1)
    def __del__(self, destroy=_PyKCS11.delete_CK_SESSION_INFO):
        try:
            if self.thisown: destroy(self)
        except: pass

class CK_SESSION_INFOPtr(CK_SESSION_INFO):
    def __init__(self, this):
        _swig_setattr(self, CK_SESSION_INFO, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, CK_SESSION_INFO, 'thisown', 0)
        _swig_setattr(self, CK_SESSION_INFO,self.__class__,CK_SESSION_INFO)
_PyKCS11.CK_SESSION_INFO_swigregister(CK_SESSION_INFOPtr)

class CK_DATE(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, CK_DATE, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, CK_DATE, name)
    def __repr__(self):
        return "<C CK_DATE instance at %s>" % (self.this,)
    def GetYear(*args): return _PyKCS11.CK_DATE_GetYear(*args)
    def GetMonth(*args): return _PyKCS11.CK_DATE_GetMonth(*args)
    def GetDay(*args): return _PyKCS11.CK_DATE_GetDay(*args)
    def __init__(self, *args):
        _swig_setattr(self, CK_DATE, 'this', _PyKCS11.new_CK_DATE(*args))
        _swig_setattr(self, CK_DATE, 'thisown', 1)
    def __del__(self, destroy=_PyKCS11.delete_CK_DATE):
        try:
            if self.thisown: destroy(self)
        except: pass

class CK_DATEPtr(CK_DATE):
    def __init__(self, this):
        _swig_setattr(self, CK_DATE, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, CK_DATE, 'thisown', 0)
        _swig_setattr(self, CK_DATE,self.__class__,CK_DATE)
_PyKCS11.CK_DATE_swigregister(CK_DATEPtr)

class CK_MECHANISM(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, CK_MECHANISM, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, CK_MECHANISM, name)
    def __repr__(self):
        return "<C CK_MECHANISM instance at %s>" % (self.this,)
    __swig_setmethods__["mechanism"] = _PyKCS11.CK_MECHANISM_mechanism_set
    __swig_getmethods__["mechanism"] = _PyKCS11.CK_MECHANISM_mechanism_get
    if _newclass:mechanism = property(_PyKCS11.CK_MECHANISM_mechanism_get, _PyKCS11.CK_MECHANISM_mechanism_set)
    __swig_setmethods__["pParameter"] = _PyKCS11.CK_MECHANISM_pParameter_set
    __swig_getmethods__["pParameter"] = _PyKCS11.CK_MECHANISM_pParameter_get
    if _newclass:pParameter = property(_PyKCS11.CK_MECHANISM_pParameter_get, _PyKCS11.CK_MECHANISM_pParameter_set)
    __swig_setmethods__["ulParameterLen"] = _PyKCS11.CK_MECHANISM_ulParameterLen_set
    __swig_getmethods__["ulParameterLen"] = _PyKCS11.CK_MECHANISM_ulParameterLen_get
    if _newclass:ulParameterLen = property(_PyKCS11.CK_MECHANISM_ulParameterLen_get, _PyKCS11.CK_MECHANISM_ulParameterLen_set)
    def __init__(self, *args):
        _swig_setattr(self, CK_MECHANISM, 'this', _PyKCS11.new_CK_MECHANISM(*args))
        _swig_setattr(self, CK_MECHANISM, 'thisown', 1)
    def __del__(self, destroy=_PyKCS11.delete_CK_MECHANISM):
        try:
            if self.thisown: destroy(self)
        except: pass

class CK_MECHANISMPtr(CK_MECHANISM):
    def __init__(self, this):
        _swig_setattr(self, CK_MECHANISM, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, CK_MECHANISM, 'thisown', 0)
        _swig_setattr(self, CK_MECHANISM,self.__class__,CK_MECHANISM)
_PyKCS11.CK_MECHANISM_swigregister(CK_MECHANISMPtr)

class CK_MECHANISM_INFO(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, CK_MECHANISM_INFO, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, CK_MECHANISM_INFO, name)
    def __repr__(self):
        return "<C CK_MECHANISM_INFO instance at %s>" % (self.this,)
    __swig_getmethods__["ulMinKeySize"] = _PyKCS11.CK_MECHANISM_INFO_ulMinKeySize_get
    if _newclass:ulMinKeySize = property(_PyKCS11.CK_MECHANISM_INFO_ulMinKeySize_get)
    __swig_getmethods__["ulMaxKeySize"] = _PyKCS11.CK_MECHANISM_INFO_ulMaxKeySize_get
    if _newclass:ulMaxKeySize = property(_PyKCS11.CK_MECHANISM_INFO_ulMaxKeySize_get)
    __swig_getmethods__["flags"] = _PyKCS11.CK_MECHANISM_INFO_flags_get
    if _newclass:flags = property(_PyKCS11.CK_MECHANISM_INFO_flags_get)
    def __init__(self, *args):
        _swig_setattr(self, CK_MECHANISM_INFO, 'this', _PyKCS11.new_CK_MECHANISM_INFO(*args))
        _swig_setattr(self, CK_MECHANISM_INFO, 'thisown', 1)
    def __del__(self, destroy=_PyKCS11.delete_CK_MECHANISM_INFO):
        try:
            if self.thisown: destroy(self)
        except: pass

class CK_MECHANISM_INFOPtr(CK_MECHANISM_INFO):
    def __init__(self, this):
        _swig_setattr(self, CK_MECHANISM_INFO, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, CK_MECHANISM_INFO, 'thisown', 0)
        _swig_setattr(self, CK_MECHANISM_INFO,self.__class__,CK_MECHANISM_INFO)
_PyKCS11.CK_MECHANISM_INFO_swigregister(CK_MECHANISM_INFOPtr)

FALSE = _PyKCS11.FALSE
TRUE = _PyKCS11.TRUE
CK_TRUE = _PyKCS11.CK_TRUE
CK_FALSE = _PyKCS11.CK_FALSE
CK_UNAVAILABLE_INFORMATION = _PyKCS11.CK_UNAVAILABLE_INFORMATION
CK_EFFECTIVELY_INFINITE = _PyKCS11.CK_EFFECTIVELY_INFINITE
CK_INVALID_HANDLE = _PyKCS11.CK_INVALID_HANDLE
CKN_SURRENDER = _PyKCS11.CKN_SURRENDER
CKF_TOKEN_PRESENT = _PyKCS11.CKF_TOKEN_PRESENT
CKF_REMOVABLE_DEVICE = _PyKCS11.CKF_REMOVABLE_DEVICE
CKF_HW_SLOT = _PyKCS11.CKF_HW_SLOT
CKF_RNG = _PyKCS11.CKF_RNG
CKF_WRITE_PROTECTED = _PyKCS11.CKF_WRITE_PROTECTED
CKF_LOGIN_REQUIRED = _PyKCS11.CKF_LOGIN_REQUIRED
CKF_USER_PIN_INITIALIZED = _PyKCS11.CKF_USER_PIN_INITIALIZED
CKF_RESTORE_KEY_NOT_NEEDED = _PyKCS11.CKF_RESTORE_KEY_NOT_NEEDED
CKF_CLOCK_ON_TOKEN = _PyKCS11.CKF_CLOCK_ON_TOKEN
CKF_PROTECTED_AUTHENTICATION_PATH = _PyKCS11.CKF_PROTECTED_AUTHENTICATION_PATH
CKF_DUAL_CRYPTO_OPERATIONS = _PyKCS11.CKF_DUAL_CRYPTO_OPERATIONS
CKF_TOKEN_INITIALIZED = _PyKCS11.CKF_TOKEN_INITIALIZED
CKF_SECONDARY_AUTHENTICATION = _PyKCS11.CKF_SECONDARY_AUTHENTICATION
CKF_USER_PIN_COUNT_LOW = _PyKCS11.CKF_USER_PIN_COUNT_LOW
CKF_USER_PIN_FINAL_TRY = _PyKCS11.CKF_USER_PIN_FINAL_TRY
CKF_USER_PIN_LOCKED = _PyKCS11.CKF_USER_PIN_LOCKED
CKF_USER_PIN_TO_BE_CHANGED = _PyKCS11.CKF_USER_PIN_TO_BE_CHANGED
CKF_SO_PIN_COUNT_LOW = _PyKCS11.CKF_SO_PIN_COUNT_LOW
CKF_SO_PIN_FINAL_TRY = _PyKCS11.CKF_SO_PIN_FINAL_TRY
CKF_SO_PIN_LOCKED = _PyKCS11.CKF_SO_PIN_LOCKED
CKF_SO_PIN_TO_BE_CHANGED = _PyKCS11.CKF_SO_PIN_TO_BE_CHANGED
CKU_SO = _PyKCS11.CKU_SO
CKU_USER = _PyKCS11.CKU_USER
CKS_RO_PUBLIC_SESSION = _PyKCS11.CKS_RO_PUBLIC_SESSION
CKS_RO_USER_FUNCTIONS = _PyKCS11.CKS_RO_USER_FUNCTIONS
CKS_RW_PUBLIC_SESSION = _PyKCS11.CKS_RW_PUBLIC_SESSION
CKS_RW_USER_FUNCTIONS = _PyKCS11.CKS_RW_USER_FUNCTIONS
CKS_RW_SO_FUNCTIONS = _PyKCS11.CKS_RW_SO_FUNCTIONS
CKF_RW_SESSION = _PyKCS11.CKF_RW_SESSION
CKF_SERIAL_SESSION = _PyKCS11.CKF_SERIAL_SESSION
CKO_DATA = _PyKCS11.CKO_DATA
CKO_CERTIFICATE = _PyKCS11.CKO_CERTIFICATE
CKO_PUBLIC_KEY = _PyKCS11.CKO_PUBLIC_KEY
CKO_PRIVATE_KEY = _PyKCS11.CKO_PRIVATE_KEY
CKO_SECRET_KEY = _PyKCS11.CKO_SECRET_KEY
CKO_HW_FEATURE = _PyKCS11.CKO_HW_FEATURE
CKO_DOMAIN_PARAMETERS = _PyKCS11.CKO_DOMAIN_PARAMETERS
CKO_VENDOR_DEFINED = _PyKCS11.CKO_VENDOR_DEFINED
CKH_MONOTONIC_COUNTER = _PyKCS11.CKH_MONOTONIC_COUNTER
CKH_CLOCK = _PyKCS11.CKH_CLOCK
CKH_VENDOR_DEFINED = _PyKCS11.CKH_VENDOR_DEFINED
CKK_RSA = _PyKCS11.CKK_RSA
CKK_DSA = _PyKCS11.CKK_DSA
CKK_DH = _PyKCS11.CKK_DH
CKK_ECDSA = _PyKCS11.CKK_ECDSA
CKK_EC = _PyKCS11.CKK_EC
CKK_X9_42_DH = _PyKCS11.CKK_X9_42_DH
CKK_KEA = _PyKCS11.CKK_KEA
CKK_GENERIC_SECRET = _PyKCS11.CKK_GENERIC_SECRET
CKK_RC2 = _PyKCS11.CKK_RC2
CKK_RC4 = _PyKCS11.CKK_RC4
CKK_DES = _PyKCS11.CKK_DES
CKK_DES2 = _PyKCS11.CKK_DES2
CKK_DES3 = _PyKCS11.CKK_DES3
CKK_CAST = _PyKCS11.CKK_CAST
CKK_CAST3 = _PyKCS11.CKK_CAST3
CKK_CAST5 = _PyKCS11.CKK_CAST5
CKK_CAST128 = _PyKCS11.CKK_CAST128
CKK_RC5 = _PyKCS11.CKK_RC5
CKK_IDEA = _PyKCS11.CKK_IDEA
CKK_SKIPJACK = _PyKCS11.CKK_SKIPJACK
CKK_BATON = _PyKCS11.CKK_BATON
CKK_JUNIPER = _PyKCS11.CKK_JUNIPER
CKK_CDMF = _PyKCS11.CKK_CDMF
CKK_AES = _PyKCS11.CKK_AES
CKK_VENDOR_DEFINED = _PyKCS11.CKK_VENDOR_DEFINED
CKC_X_509 = _PyKCS11.CKC_X_509
CKC_X_509_ATTR_CERT = _PyKCS11.CKC_X_509_ATTR_CERT
CKC_VENDOR_DEFINED = _PyKCS11.CKC_VENDOR_DEFINED
CKA_CLASS = _PyKCS11.CKA_CLASS
CKA_TOKEN = _PyKCS11.CKA_TOKEN
CKA_PRIVATE = _PyKCS11.CKA_PRIVATE
CKA_LABEL = _PyKCS11.CKA_LABEL
CKA_APPLICATION = _PyKCS11.CKA_APPLICATION
CKA_VALUE = _PyKCS11.CKA_VALUE
CKA_OBJECT_ID = _PyKCS11.CKA_OBJECT_ID
CKA_CERTIFICATE_TYPE = _PyKCS11.CKA_CERTIFICATE_TYPE
CKA_ISSUER = _PyKCS11.CKA_ISSUER
CKA_SERIAL_NUMBER = _PyKCS11.CKA_SERIAL_NUMBER
CKA_AC_ISSUER = _PyKCS11.CKA_AC_ISSUER
CKA_OWNER = _PyKCS11.CKA_OWNER
CKA_ATTR_TYPES = _PyKCS11.CKA_ATTR_TYPES
CKA_TRUSTED = _PyKCS11.CKA_TRUSTED
CKA_KEY_TYPE = _PyKCS11.CKA_KEY_TYPE
CKA_SUBJECT = _PyKCS11.CKA_SUBJECT
CKA_ID = _PyKCS11.CKA_ID
CKA_SENSITIVE = _PyKCS11.CKA_SENSITIVE
CKA_ENCRYPT = _PyKCS11.CKA_ENCRYPT
CKA_DECRYPT = _PyKCS11.CKA_DECRYPT
CKA_WRAP = _PyKCS11.CKA_WRAP
CKA_UNWRAP = _PyKCS11.CKA_UNWRAP
CKA_SIGN = _PyKCS11.CKA_SIGN
CKA_SIGN_RECOVER = _PyKCS11.CKA_SIGN_RECOVER
CKA_VERIFY = _PyKCS11.CKA_VERIFY
CKA_VERIFY_RECOVER = _PyKCS11.CKA_VERIFY_RECOVER
CKA_DERIVE = _PyKCS11.CKA_DERIVE
CKA_START_DATE = _PyKCS11.CKA_START_DATE
CKA_END_DATE = _PyKCS11.CKA_END_DATE
CKA_MODULUS = _PyKCS11.CKA_MODULUS
CKA_MODULUS_BITS = _PyKCS11.CKA_MODULUS_BITS
CKA_PUBLIC_EXPONENT = _PyKCS11.CKA_PUBLIC_EXPONENT
CKA_PRIVATE_EXPONENT = _PyKCS11.CKA_PRIVATE_EXPONENT
CKA_PRIME_1 = _PyKCS11.CKA_PRIME_1
CKA_PRIME_2 = _PyKCS11.CKA_PRIME_2
CKA_EXPONENT_1 = _PyKCS11.CKA_EXPONENT_1
CKA_EXPONENT_2 = _PyKCS11.CKA_EXPONENT_2
CKA_COEFFICIENT = _PyKCS11.CKA_COEFFICIENT
CKA_PRIME = _PyKCS11.CKA_PRIME
CKA_SUBPRIME = _PyKCS11.CKA_SUBPRIME
CKA_BASE = _PyKCS11.CKA_BASE
CKA_PRIME_BITS = _PyKCS11.CKA_PRIME_BITS
CKA_SUBPRIME_BITS = _PyKCS11.CKA_SUBPRIME_BITS
CKA_SUB_PRIME_BITS = _PyKCS11.CKA_SUB_PRIME_BITS
CKA_VALUE_BITS = _PyKCS11.CKA_VALUE_BITS
CKA_VALUE_LEN = _PyKCS11.CKA_VALUE_LEN
CKA_EXTRACTABLE = _PyKCS11.CKA_EXTRACTABLE
CKA_LOCAL = _PyKCS11.CKA_LOCAL
CKA_NEVER_EXTRACTABLE = _PyKCS11.CKA_NEVER_EXTRACTABLE
CKA_ALWAYS_SENSITIVE = _PyKCS11.CKA_ALWAYS_SENSITIVE
CKA_KEY_GEN_MECHANISM = _PyKCS11.CKA_KEY_GEN_MECHANISM
CKA_MODIFIABLE = _PyKCS11.CKA_MODIFIABLE
CKA_ECDSA_PARAMS = _PyKCS11.CKA_ECDSA_PARAMS
CKA_EC_PARAMS = _PyKCS11.CKA_EC_PARAMS
CKA_EC_POINT = _PyKCS11.CKA_EC_POINT
CKA_SECONDARY_AUTH = _PyKCS11.CKA_SECONDARY_AUTH
CKA_AUTH_PIN_FLAGS = _PyKCS11.CKA_AUTH_PIN_FLAGS
CKA_HW_FEATURE_TYPE = _PyKCS11.CKA_HW_FEATURE_TYPE
CKA_RESET_ON_INIT = _PyKCS11.CKA_RESET_ON_INIT
CKA_HAS_RESET = _PyKCS11.CKA_HAS_RESET
CKA_VENDOR_DEFINED = _PyKCS11.CKA_VENDOR_DEFINED
CKM_RSA_PKCS_KEY_PAIR_GEN = _PyKCS11.CKM_RSA_PKCS_KEY_PAIR_GEN
CKM_RSA_PKCS = _PyKCS11.CKM_RSA_PKCS
CKM_RSA_9796 = _PyKCS11.CKM_RSA_9796
CKM_RSA_X_509 = _PyKCS11.CKM_RSA_X_509
CKM_MD2_RSA_PKCS = _PyKCS11.CKM_MD2_RSA_PKCS
CKM_MD5_RSA_PKCS = _PyKCS11.CKM_MD5_RSA_PKCS
CKM_SHA1_RSA_PKCS = _PyKCS11.CKM_SHA1_RSA_PKCS
CKM_RIPEMD128_RSA_PKCS = _PyKCS11.CKM_RIPEMD128_RSA_PKCS
CKM_RIPEMD160_RSA_PKCS = _PyKCS11.CKM_RIPEMD160_RSA_PKCS
CKM_RSA_PKCS_OAEP = _PyKCS11.CKM_RSA_PKCS_OAEP
CKM_RSA_X9_31_KEY_PAIR_GEN = _PyKCS11.CKM_RSA_X9_31_KEY_PAIR_GEN
CKM_RSA_X9_31 = _PyKCS11.CKM_RSA_X9_31
CKM_SHA1_RSA_X9_31 = _PyKCS11.CKM_SHA1_RSA_X9_31
CKM_RSA_PKCS_PSS = _PyKCS11.CKM_RSA_PKCS_PSS
CKM_SHA1_RSA_PKCS_PSS = _PyKCS11.CKM_SHA1_RSA_PKCS_PSS
CKM_DSA_KEY_PAIR_GEN = _PyKCS11.CKM_DSA_KEY_PAIR_GEN
CKM_DSA = _PyKCS11.CKM_DSA
CKM_DSA_SHA1 = _PyKCS11.CKM_DSA_SHA1
CKM_DH_PKCS_KEY_PAIR_GEN = _PyKCS11.CKM_DH_PKCS_KEY_PAIR_GEN
CKM_DH_PKCS_DERIVE = _PyKCS11.CKM_DH_PKCS_DERIVE
CKM_X9_42_DH_KEY_PAIR_GEN = _PyKCS11.CKM_X9_42_DH_KEY_PAIR_GEN
CKM_X9_42_DH_DERIVE = _PyKCS11.CKM_X9_42_DH_DERIVE
CKM_X9_42_DH_HYBRID_DERIVE = _PyKCS11.CKM_X9_42_DH_HYBRID_DERIVE
CKM_X9_42_MQV_DERIVE = _PyKCS11.CKM_X9_42_MQV_DERIVE
CKM_RC2_KEY_GEN = _PyKCS11.CKM_RC2_KEY_GEN
CKM_RC2_ECB = _PyKCS11.CKM_RC2_ECB
CKM_RC2_CBC = _PyKCS11.CKM_RC2_CBC
CKM_RC2_MAC = _PyKCS11.CKM_RC2_MAC
CKM_RC2_MAC_GENERAL = _PyKCS11.CKM_RC2_MAC_GENERAL
CKM_RC2_CBC_PAD = _PyKCS11.CKM_RC2_CBC_PAD
CKM_RC4_KEY_GEN = _PyKCS11.CKM_RC4_KEY_GEN
CKM_RC4 = _PyKCS11.CKM_RC4
CKM_DES_KEY_GEN = _PyKCS11.CKM_DES_KEY_GEN
CKM_DES_ECB = _PyKCS11.CKM_DES_ECB
CKM_DES_CBC = _PyKCS11.CKM_DES_CBC
CKM_DES_MAC = _PyKCS11.CKM_DES_MAC
CKM_DES_MAC_GENERAL = _PyKCS11.CKM_DES_MAC_GENERAL
CKM_DES_CBC_PAD = _PyKCS11.CKM_DES_CBC_PAD
CKM_DES2_KEY_GEN = _PyKCS11.CKM_DES2_KEY_GEN
CKM_DES3_KEY_GEN = _PyKCS11.CKM_DES3_KEY_GEN
CKM_DES3_ECB = _PyKCS11.CKM_DES3_ECB
CKM_DES3_CBC = _PyKCS11.CKM_DES3_CBC
CKM_DES3_MAC = _PyKCS11.CKM_DES3_MAC
CKM_DES3_MAC_GENERAL = _PyKCS11.CKM_DES3_MAC_GENERAL
CKM_DES3_CBC_PAD = _PyKCS11.CKM_DES3_CBC_PAD
CKM_CDMF_KEY_GEN = _PyKCS11.CKM_CDMF_KEY_GEN
CKM_CDMF_ECB = _PyKCS11.CKM_CDMF_ECB
CKM_CDMF_CBC = _PyKCS11.CKM_CDMF_CBC
CKM_CDMF_MAC = _PyKCS11.CKM_CDMF_MAC
CKM_CDMF_MAC_GENERAL = _PyKCS11.CKM_CDMF_MAC_GENERAL
CKM_CDMF_CBC_PAD = _PyKCS11.CKM_CDMF_CBC_PAD
CKM_MD2 = _PyKCS11.CKM_MD2
CKM_MD2_HMAC = _PyKCS11.CKM_MD2_HMAC
CKM_MD2_HMAC_GENERAL = _PyKCS11.CKM_MD2_HMAC_GENERAL
CKM_MD5 = _PyKCS11.CKM_MD5
CKM_MD5_HMAC = _PyKCS11.CKM_MD5_HMAC
CKM_MD5_HMAC_GENERAL = _PyKCS11.CKM_MD5_HMAC_GENERAL
CKM_SHA_1 = _PyKCS11.CKM_SHA_1
CKM_SHA_1_HMAC = _PyKCS11.CKM_SHA_1_HMAC
CKM_SHA_1_HMAC_GENERAL = _PyKCS11.CKM_SHA_1_HMAC_GENERAL
CKM_RIPEMD128 = _PyKCS11.CKM_RIPEMD128
CKM_RIPEMD128_HMAC = _PyKCS11.CKM_RIPEMD128_HMAC
CKM_RIPEMD128_HMAC_GENERAL = _PyKCS11.CKM_RIPEMD128_HMAC_GENERAL
CKM_RIPEMD160 = _PyKCS11.CKM_RIPEMD160
CKM_RIPEMD160_HMAC = _PyKCS11.CKM_RIPEMD160_HMAC
CKM_RIPEMD160_HMAC_GENERAL = _PyKCS11.CKM_RIPEMD160_HMAC_GENERAL
CKM_CAST_KEY_GEN = _PyKCS11.CKM_CAST_KEY_GEN
CKM_CAST_ECB = _PyKCS11.CKM_CAST_ECB
CKM_CAST_CBC = _PyKCS11.CKM_CAST_CBC
CKM_CAST_MAC = _PyKCS11.CKM_CAST_MAC
CKM_CAST_MAC_GENERAL = _PyKCS11.CKM_CAST_MAC_GENERAL
CKM_CAST_CBC_PAD = _PyKCS11.CKM_CAST_CBC_PAD
CKM_CAST3_KEY_GEN = _PyKCS11.CKM_CAST3_KEY_GEN
CKM_CAST3_ECB = _PyKCS11.CKM_CAST3_ECB
CKM_CAST3_CBC = _PyKCS11.CKM_CAST3_CBC
CKM_CAST3_MAC = _PyKCS11.CKM_CAST3_MAC
CKM_CAST3_MAC_GENERAL = _PyKCS11.CKM_CAST3_MAC_GENERAL
CKM_CAST3_CBC_PAD = _PyKCS11.CKM_CAST3_CBC_PAD
CKM_CAST5_KEY_GEN = _PyKCS11.CKM_CAST5_KEY_GEN
CKM_CAST128_KEY_GEN = _PyKCS11.CKM_CAST128_KEY_GEN
CKM_CAST5_ECB = _PyKCS11.CKM_CAST5_ECB
CKM_CAST128_ECB = _PyKCS11.CKM_CAST128_ECB
CKM_CAST5_CBC = _PyKCS11.CKM_CAST5_CBC
CKM_CAST128_CBC = _PyKCS11.CKM_CAST128_CBC
CKM_CAST5_MAC = _PyKCS11.CKM_CAST5_MAC
CKM_CAST128_MAC = _PyKCS11.CKM_CAST128_MAC
CKM_CAST5_MAC_GENERAL = _PyKCS11.CKM_CAST5_MAC_GENERAL
CKM_CAST128_MAC_GENERAL = _PyKCS11.CKM_CAST128_MAC_GENERAL
CKM_CAST5_CBC_PAD = _PyKCS11.CKM_CAST5_CBC_PAD
CKM_CAST128_CBC_PAD = _PyKCS11.CKM_CAST128_CBC_PAD
CKM_RC5_KEY_GEN = _PyKCS11.CKM_RC5_KEY_GEN
CKM_RC5_ECB = _PyKCS11.CKM_RC5_ECB
CKM_RC5_CBC = _PyKCS11.CKM_RC5_CBC
CKM_RC5_MAC = _PyKCS11.CKM_RC5_MAC
CKM_RC5_MAC_GENERAL = _PyKCS11.CKM_RC5_MAC_GENERAL
CKM_RC5_CBC_PAD = _PyKCS11.CKM_RC5_CBC_PAD
CKM_IDEA_KEY_GEN = _PyKCS11.CKM_IDEA_KEY_GEN
CKM_IDEA_ECB = _PyKCS11.CKM_IDEA_ECB
CKM_IDEA_CBC = _PyKCS11.CKM_IDEA_CBC
CKM_IDEA_MAC = _PyKCS11.CKM_IDEA_MAC
CKM_IDEA_MAC_GENERAL = _PyKCS11.CKM_IDEA_MAC_GENERAL
CKM_IDEA_CBC_PAD = _PyKCS11.CKM_IDEA_CBC_PAD
CKM_GENERIC_SECRET_KEY_GEN = _PyKCS11.CKM_GENERIC_SECRET_KEY_GEN
CKM_CONCATENATE_BASE_AND_KEY = _PyKCS11.CKM_CONCATENATE_BASE_AND_KEY
CKM_CONCATENATE_BASE_AND_DATA = _PyKCS11.CKM_CONCATENATE_BASE_AND_DATA
CKM_CONCATENATE_DATA_AND_BASE = _PyKCS11.CKM_CONCATENATE_DATA_AND_BASE
CKM_XOR_BASE_AND_DATA = _PyKCS11.CKM_XOR_BASE_AND_DATA
CKM_EXTRACT_KEY_FROM_KEY = _PyKCS11.CKM_EXTRACT_KEY_FROM_KEY
CKM_SSL3_PRE_MASTER_KEY_GEN = _PyKCS11.CKM_SSL3_PRE_MASTER_KEY_GEN
CKM_SSL3_MASTER_KEY_DERIVE = _PyKCS11.CKM_SSL3_MASTER_KEY_DERIVE
CKM_SSL3_KEY_AND_MAC_DERIVE = _PyKCS11.CKM_SSL3_KEY_AND_MAC_DERIVE
CKM_SSL3_MASTER_KEY_DERIVE_DH = _PyKCS11.CKM_SSL3_MASTER_KEY_DERIVE_DH
CKM_TLS_PRE_MASTER_KEY_GEN = _PyKCS11.CKM_TLS_PRE_MASTER_KEY_GEN
CKM_TLS_MASTER_KEY_DERIVE = _PyKCS11.CKM_TLS_MASTER_KEY_DERIVE
CKM_TLS_KEY_AND_MAC_DERIVE = _PyKCS11.CKM_TLS_KEY_AND_MAC_DERIVE
CKM_TLS_MASTER_KEY_DERIVE_DH = _PyKCS11.CKM_TLS_MASTER_KEY_DERIVE_DH
CKM_SSL3_MD5_MAC = _PyKCS11.CKM_SSL3_MD5_MAC
CKM_SSL3_SHA1_MAC = _PyKCS11.CKM_SSL3_SHA1_MAC
CKM_MD5_KEY_DERIVATION = _PyKCS11.CKM_MD5_KEY_DERIVATION
CKM_MD2_KEY_DERIVATION = _PyKCS11.CKM_MD2_KEY_DERIVATION
CKM_SHA1_KEY_DERIVATION = _PyKCS11.CKM_SHA1_KEY_DERIVATION
CKM_PBE_MD2_DES_CBC = _PyKCS11.CKM_PBE_MD2_DES_CBC
CKM_PBE_MD5_DES_CBC = _PyKCS11.CKM_PBE_MD5_DES_CBC
CKM_PBE_MD5_CAST_CBC = _PyKCS11.CKM_PBE_MD5_CAST_CBC
CKM_PBE_MD5_CAST3_CBC = _PyKCS11.CKM_PBE_MD5_CAST3_CBC
CKM_PBE_MD5_CAST5_CBC = _PyKCS11.CKM_PBE_MD5_CAST5_CBC
CKM_PBE_MD5_CAST128_CBC = _PyKCS11.CKM_PBE_MD5_CAST128_CBC
CKM_PBE_SHA1_CAST5_CBC = _PyKCS11.CKM_PBE_SHA1_CAST5_CBC
CKM_PBE_SHA1_CAST128_CBC = _PyKCS11.CKM_PBE_SHA1_CAST128_CBC
CKM_PBE_SHA1_RC4_128 = _PyKCS11.CKM_PBE_SHA1_RC4_128
CKM_PBE_SHA1_RC4_40 = _PyKCS11.CKM_PBE_SHA1_RC4_40
CKM_PBE_SHA1_DES3_EDE_CBC = _PyKCS11.CKM_PBE_SHA1_DES3_EDE_CBC
CKM_PBE_SHA1_DES2_EDE_CBC = _PyKCS11.CKM_PBE_SHA1_DES2_EDE_CBC
CKM_PBE_SHA1_RC2_128_CBC = _PyKCS11.CKM_PBE_SHA1_RC2_128_CBC
CKM_PBE_SHA1_RC2_40_CBC = _PyKCS11.CKM_PBE_SHA1_RC2_40_CBC
CKM_PKCS5_PBKD2 = _PyKCS11.CKM_PKCS5_PBKD2
CKM_PBA_SHA1_WITH_SHA1_HMAC = _PyKCS11.CKM_PBA_SHA1_WITH_SHA1_HMAC
CKM_KEY_WRAP_LYNKS = _PyKCS11.CKM_KEY_WRAP_LYNKS
CKM_KEY_WRAP_SET_OAEP = _PyKCS11.CKM_KEY_WRAP_SET_OAEP
CKM_SKIPJACK_KEY_GEN = _PyKCS11.CKM_SKIPJACK_KEY_GEN
CKM_SKIPJACK_ECB64 = _PyKCS11.CKM_SKIPJACK_ECB64
CKM_SKIPJACK_CBC64 = _PyKCS11.CKM_SKIPJACK_CBC64
CKM_SKIPJACK_OFB64 = _PyKCS11.CKM_SKIPJACK_OFB64
CKM_SKIPJACK_CFB64 = _PyKCS11.CKM_SKIPJACK_CFB64
CKM_SKIPJACK_CFB32 = _PyKCS11.CKM_SKIPJACK_CFB32
CKM_SKIPJACK_CFB16 = _PyKCS11.CKM_SKIPJACK_CFB16
CKM_SKIPJACK_CFB8 = _PyKCS11.CKM_SKIPJACK_CFB8
CKM_SKIPJACK_WRAP = _PyKCS11.CKM_SKIPJACK_WRAP
CKM_SKIPJACK_PRIVATE_WRAP = _PyKCS11.CKM_SKIPJACK_PRIVATE_WRAP
CKM_SKIPJACK_RELAYX = _PyKCS11.CKM_SKIPJACK_RELAYX
CKM_KEA_KEY_PAIR_GEN = _PyKCS11.CKM_KEA_KEY_PAIR_GEN
CKM_KEA_KEY_DERIVE = _PyKCS11.CKM_KEA_KEY_DERIVE
CKM_FORTEZZA_TIMESTAMP = _PyKCS11.CKM_FORTEZZA_TIMESTAMP
CKM_BATON_KEY_GEN = _PyKCS11.CKM_BATON_KEY_GEN
CKM_BATON_ECB128 = _PyKCS11.CKM_BATON_ECB128
CKM_BATON_ECB96 = _PyKCS11.CKM_BATON_ECB96
CKM_BATON_CBC128 = _PyKCS11.CKM_BATON_CBC128
CKM_BATON_COUNTER = _PyKCS11.CKM_BATON_COUNTER
CKM_BATON_SHUFFLE = _PyKCS11.CKM_BATON_SHUFFLE
CKM_BATON_WRAP = _PyKCS11.CKM_BATON_WRAP
CKM_ECDSA_KEY_PAIR_GEN = _PyKCS11.CKM_ECDSA_KEY_PAIR_GEN
CKM_EC_KEY_PAIR_GEN = _PyKCS11.CKM_EC_KEY_PAIR_GEN
CKM_ECDSA = _PyKCS11.CKM_ECDSA
CKM_ECDSA_SHA1 = _PyKCS11.CKM_ECDSA_SHA1
CKM_ECDH1_DERIVE = _PyKCS11.CKM_ECDH1_DERIVE
CKM_ECDH1_COFACTOR_DERIVE = _PyKCS11.CKM_ECDH1_COFACTOR_DERIVE
CKM_ECMQV_DERIVE = _PyKCS11.CKM_ECMQV_DERIVE
CKM_JUNIPER_KEY_GEN = _PyKCS11.CKM_JUNIPER_KEY_GEN
CKM_JUNIPER_ECB128 = _PyKCS11.CKM_JUNIPER_ECB128
CKM_JUNIPER_CBC128 = _PyKCS11.CKM_JUNIPER_CBC128
CKM_JUNIPER_COUNTER = _PyKCS11.CKM_JUNIPER_COUNTER
CKM_JUNIPER_SHUFFLE = _PyKCS11.CKM_JUNIPER_SHUFFLE
CKM_JUNIPER_WRAP = _PyKCS11.CKM_JUNIPER_WRAP
CKM_FASTHASH = _PyKCS11.CKM_FASTHASH
CKM_AES_KEY_GEN = _PyKCS11.CKM_AES_KEY_GEN
CKM_AES_ECB = _PyKCS11.CKM_AES_ECB
CKM_AES_CBC = _PyKCS11.CKM_AES_CBC
CKM_AES_MAC = _PyKCS11.CKM_AES_MAC
CKM_AES_MAC_GENERAL = _PyKCS11.CKM_AES_MAC_GENERAL
CKM_AES_CBC_PAD = _PyKCS11.CKM_AES_CBC_PAD
CKM_DSA_PARAMETER_GEN = _PyKCS11.CKM_DSA_PARAMETER_GEN
CKM_DH_PKCS_PARAMETER_GEN = _PyKCS11.CKM_DH_PKCS_PARAMETER_GEN
CKM_X9_42_DH_PARAMETER_GEN = _PyKCS11.CKM_X9_42_DH_PARAMETER_GEN
CKM_VENDOR_DEFINED = _PyKCS11.CKM_VENDOR_DEFINED
CKF_HW = _PyKCS11.CKF_HW
CKF_ENCRYPT = _PyKCS11.CKF_ENCRYPT
CKF_DECRYPT = _PyKCS11.CKF_DECRYPT
CKF_DIGEST = _PyKCS11.CKF_DIGEST
CKF_SIGN = _PyKCS11.CKF_SIGN
CKF_SIGN_RECOVER = _PyKCS11.CKF_SIGN_RECOVER
CKF_VERIFY = _PyKCS11.CKF_VERIFY
CKF_VERIFY_RECOVER = _PyKCS11.CKF_VERIFY_RECOVER
CKF_GENERATE = _PyKCS11.CKF_GENERATE
CKF_GENERATE_KEY_PAIR = _PyKCS11.CKF_GENERATE_KEY_PAIR
CKF_WRAP = _PyKCS11.CKF_WRAP
CKF_UNWRAP = _PyKCS11.CKF_UNWRAP
CKF_DERIVE = _PyKCS11.CKF_DERIVE
CKF_EC_F_P = _PyKCS11.CKF_EC_F_P
CKF_EC_F_2M = _PyKCS11.CKF_EC_F_2M
CKF_EC_ECPARAMETERS = _PyKCS11.CKF_EC_ECPARAMETERS
CKF_EC_NAMEDCURVE = _PyKCS11.CKF_EC_NAMEDCURVE
CKF_EC_UNCOMPRESS = _PyKCS11.CKF_EC_UNCOMPRESS
CKF_EC_COMPRESS = _PyKCS11.CKF_EC_COMPRESS
CKF_EXTENSION = _PyKCS11.CKF_EXTENSION
CKR_OK = _PyKCS11.CKR_OK
CKR_CANCEL = _PyKCS11.CKR_CANCEL
CKR_HOST_MEMORY = _PyKCS11.CKR_HOST_MEMORY
CKR_SLOT_ID_INVALID = _PyKCS11.CKR_SLOT_ID_INVALID
CKR_GENERAL_ERROR = _PyKCS11.CKR_GENERAL_ERROR
CKR_FUNCTION_FAILED = _PyKCS11.CKR_FUNCTION_FAILED
CKR_ARGUMENTS_BAD = _PyKCS11.CKR_ARGUMENTS_BAD
CKR_NO_EVENT = _PyKCS11.CKR_NO_EVENT
CKR_NEED_TO_CREATE_THREADS = _PyKCS11.CKR_NEED_TO_CREATE_THREADS
CKR_CANT_LOCK = _PyKCS11.CKR_CANT_LOCK
CKR_ATTRIBUTE_READ_ONLY = _PyKCS11.CKR_ATTRIBUTE_READ_ONLY
CKR_ATTRIBUTE_SENSITIVE = _PyKCS11.CKR_ATTRIBUTE_SENSITIVE
CKR_ATTRIBUTE_TYPE_INVALID = _PyKCS11.CKR_ATTRIBUTE_TYPE_INVALID
CKR_ATTRIBUTE_VALUE_INVALID = _PyKCS11.CKR_ATTRIBUTE_VALUE_INVALID
CKR_DATA_INVALID = _PyKCS11.CKR_DATA_INVALID
CKR_DATA_LEN_RANGE = _PyKCS11.CKR_DATA_LEN_RANGE
CKR_DEVICE_ERROR = _PyKCS11.CKR_DEVICE_ERROR
CKR_DEVICE_MEMORY = _PyKCS11.CKR_DEVICE_MEMORY
CKR_DEVICE_REMOVED = _PyKCS11.CKR_DEVICE_REMOVED
CKR_ENCRYPTED_DATA_INVALID = _PyKCS11.CKR_ENCRYPTED_DATA_INVALID
CKR_ENCRYPTED_DATA_LEN_RANGE = _PyKCS11.CKR_ENCRYPTED_DATA_LEN_RANGE
CKR_FUNCTION_CANCELED = _PyKCS11.CKR_FUNCTION_CANCELED
CKR_FUNCTION_NOT_PARALLEL = _PyKCS11.CKR_FUNCTION_NOT_PARALLEL
CKR_FUNCTION_NOT_SUPPORTED = _PyKCS11.CKR_FUNCTION_NOT_SUPPORTED
CKR_KEY_HANDLE_INVALID = _PyKCS11.CKR_KEY_HANDLE_INVALID
CKR_KEY_SIZE_RANGE = _PyKCS11.CKR_KEY_SIZE_RANGE
CKR_KEY_TYPE_INCONSISTENT = _PyKCS11.CKR_KEY_TYPE_INCONSISTENT
CKR_KEY_NOT_NEEDED = _PyKCS11.CKR_KEY_NOT_NEEDED
CKR_KEY_CHANGED = _PyKCS11.CKR_KEY_CHANGED
CKR_KEY_NEEDED = _PyKCS11.CKR_KEY_NEEDED
CKR_KEY_INDIGESTIBLE = _PyKCS11.CKR_KEY_INDIGESTIBLE
CKR_KEY_FUNCTION_NOT_PERMITTED = _PyKCS11.CKR_KEY_FUNCTION_NOT_PERMITTED
CKR_KEY_NOT_WRAPPABLE = _PyKCS11.CKR_KEY_NOT_WRAPPABLE
CKR_KEY_UNEXTRACTABLE = _PyKCS11.CKR_KEY_UNEXTRACTABLE
CKR_MECHANISM_INVALID = _PyKCS11.CKR_MECHANISM_INVALID
CKR_MECHANISM_PARAM_INVALID = _PyKCS11.CKR_MECHANISM_PARAM_INVALID
CKR_OBJECT_HANDLE_INVALID = _PyKCS11.CKR_OBJECT_HANDLE_INVALID
CKR_OPERATION_ACTIVE = _PyKCS11.CKR_OPERATION_ACTIVE
CKR_OPERATION_NOT_INITIALIZED = _PyKCS11.CKR_OPERATION_NOT_INITIALIZED
CKR_PIN_INCORRECT = _PyKCS11.CKR_PIN_INCORRECT
CKR_PIN_INVALID = _PyKCS11.CKR_PIN_INVALID
CKR_PIN_LEN_RANGE = _PyKCS11.CKR_PIN_LEN_RANGE
CKR_PIN_EXPIRED = _PyKCS11.CKR_PIN_EXPIRED
CKR_PIN_LOCKED = _PyKCS11.CKR_PIN_LOCKED
CKR_SESSION_CLOSED = _PyKCS11.CKR_SESSION_CLOSED
CKR_SESSION_COUNT = _PyKCS11.CKR_SESSION_COUNT
CKR_SESSION_HANDLE_INVALID = _PyKCS11.CKR_SESSION_HANDLE_INVALID
CKR_SESSION_PARALLEL_NOT_SUPPORTED = _PyKCS11.CKR_SESSION_PARALLEL_NOT_SUPPORTED
CKR_SESSION_READ_ONLY = _PyKCS11.CKR_SESSION_READ_ONLY
CKR_SESSION_EXISTS = _PyKCS11.CKR_SESSION_EXISTS
CKR_SESSION_READ_ONLY_EXISTS = _PyKCS11.CKR_SESSION_READ_ONLY_EXISTS
CKR_SESSION_READ_WRITE_SO_EXISTS = _PyKCS11.CKR_SESSION_READ_WRITE_SO_EXISTS
CKR_SIGNATURE_INVALID = _PyKCS11.CKR_SIGNATURE_INVALID
CKR_SIGNATURE_LEN_RANGE = _PyKCS11.CKR_SIGNATURE_LEN_RANGE
CKR_TEMPLATE_INCOMPLETE = _PyKCS11.CKR_TEMPLATE_INCOMPLETE
CKR_TEMPLATE_INCONSISTENT = _PyKCS11.CKR_TEMPLATE_INCONSISTENT
CKR_TOKEN_NOT_PRESENT = _PyKCS11.CKR_TOKEN_NOT_PRESENT
CKR_TOKEN_NOT_RECOGNIZED = _PyKCS11.CKR_TOKEN_NOT_RECOGNIZED
CKR_TOKEN_WRITE_PROTECTED = _PyKCS11.CKR_TOKEN_WRITE_PROTECTED
CKR_UNWRAPPING_KEY_HANDLE_INVALID = _PyKCS11.CKR_UNWRAPPING_KEY_HANDLE_INVALID
CKR_UNWRAPPING_KEY_SIZE_RANGE = _PyKCS11.CKR_UNWRAPPING_KEY_SIZE_RANGE
CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = _PyKCS11.CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT
CKR_USER_ALREADY_LOGGED_IN = _PyKCS11.CKR_USER_ALREADY_LOGGED_IN
CKR_USER_NOT_LOGGED_IN = _PyKCS11.CKR_USER_NOT_LOGGED_IN
CKR_USER_PIN_NOT_INITIALIZED = _PyKCS11.CKR_USER_PIN_NOT_INITIALIZED
CKR_USER_TYPE_INVALID = _PyKCS11.CKR_USER_TYPE_INVALID
CKR_USER_ANOTHER_ALREADY_LOGGED_IN = _PyKCS11.CKR_USER_ANOTHER_ALREADY_LOGGED_IN
CKR_USER_TOO_MANY_TYPES = _PyKCS11.CKR_USER_TOO_MANY_TYPES
CKR_WRAPPED_KEY_INVALID = _PyKCS11.CKR_WRAPPED_KEY_INVALID
CKR_WRAPPED_KEY_LEN_RANGE = _PyKCS11.CKR_WRAPPED_KEY_LEN_RANGE
CKR_WRAPPING_KEY_HANDLE_INVALID = _PyKCS11.CKR_WRAPPING_KEY_HANDLE_INVALID
CKR_WRAPPING_KEY_SIZE_RANGE = _PyKCS11.CKR_WRAPPING_KEY_SIZE_RANGE
CKR_WRAPPING_KEY_TYPE_INCONSISTENT = _PyKCS11.CKR_WRAPPING_KEY_TYPE_INCONSISTENT
CKR_RANDOM_SEED_NOT_SUPPORTED = _PyKCS11.CKR_RANDOM_SEED_NOT_SUPPORTED
CKR_RANDOM_NO_RNG = _PyKCS11.CKR_RANDOM_NO_RNG
CKR_DOMAIN_PARAMS_INVALID = _PyKCS11.CKR_DOMAIN_PARAMS_INVALID
CKR_BUFFER_TOO_SMALL = _PyKCS11.CKR_BUFFER_TOO_SMALL
CKR_SAVED_STATE_INVALID = _PyKCS11.CKR_SAVED_STATE_INVALID
CKR_INFORMATION_SENSITIVE = _PyKCS11.CKR_INFORMATION_SENSITIVE
CKR_STATE_UNSAVEABLE = _PyKCS11.CKR_STATE_UNSAVEABLE
CKR_CRYPTOKI_NOT_INITIALIZED = _PyKCS11.CKR_CRYPTOKI_NOT_INITIALIZED
CKR_CRYPTOKI_ALREADY_INITIALIZED = _PyKCS11.CKR_CRYPTOKI_ALREADY_INITIALIZED
CKR_MUTEX_BAD = _PyKCS11.CKR_MUTEX_BAD
CKR_MUTEX_NOT_LOCKED = _PyKCS11.CKR_MUTEX_NOT_LOCKED
CKR_VENDOR_DEFINED = _PyKCS11.CKR_VENDOR_DEFINED
CKF_LIBRARY_CANT_CREATE_OS_THREADS = _PyKCS11.CKF_LIBRARY_CANT_CREATE_OS_THREADS
CKF_OS_LOCKING_OK = _PyKCS11.CKF_OS_LOCKING_OK
CKF_DONT_BLOCK = _PyKCS11.CKF_DONT_BLOCK
CKG_MGF1_SHA1 = _PyKCS11.CKG_MGF1_SHA1
CKZ_DATA_SPECIFIED = _PyKCS11.CKZ_DATA_SPECIFIED
CKD_NULL = _PyKCS11.CKD_NULL
CKD_SHA1_KDF = _PyKCS11.CKD_SHA1_KDF
CKD_SHA1_KDF_ASN1 = _PyKCS11.CKD_SHA1_KDF_ASN1
CKD_SHA1_KDF_CONCATENATE = _PyKCS11.CKD_SHA1_KDF_CONCATENATE
CKP_PKCS5_PBKD2_HMAC_SHA1 = _PyKCS11.CKP_PKCS5_PBKD2_HMAC_SHA1
CKZ_SALT_SPECIFIED = _PyKCS11.CKZ_SALT_SPECIFIED
class CPKCS11Lib(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, CPKCS11Lib, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, CPKCS11Lib, name)
    def __repr__(self):
        return "<C CPKCS11Lib instance at %s>" % (self.this,)
    def __init__(self, *args):
        _swig_setattr(self, CPKCS11Lib, 'this', _PyKCS11.new_CPKCS11Lib(*args))
        _swig_setattr(self, CPKCS11Lib, 'thisown', 1)
    def __del__(self, destroy=_PyKCS11.delete_CPKCS11Lib):
        try:
            if self.thisown: destroy(self)
        except: pass
    def Load(*args): return _PyKCS11.CPKCS11Lib_Load(*args)
    def Unload(*args): return _PyKCS11.CPKCS11Lib_Unload(*args)
    def C_Initialize(*args): return _PyKCS11.CPKCS11Lib_C_Initialize(*args)
    def C_Finalize(*args): return _PyKCS11.CPKCS11Lib_C_Finalize(*args)
    def C_GetInfo(*args): return _PyKCS11.CPKCS11Lib_C_GetInfo(*args)
    def C_GetSlotList(*args): return _PyKCS11.CPKCS11Lib_C_GetSlotList(*args)
    def C_GetSlotInfo(*args): return _PyKCS11.CPKCS11Lib_C_GetSlotInfo(*args)
    def C_GetTokenInfo(*args): return _PyKCS11.CPKCS11Lib_C_GetTokenInfo(*args)
    def C_InitToken(*args): return _PyKCS11.CPKCS11Lib_C_InitToken(*args)
    def C_InitPIN(*args): return _PyKCS11.CPKCS11Lib_C_InitPIN(*args)
    def C_SetPIN(*args): return _PyKCS11.CPKCS11Lib_C_SetPIN(*args)
    def C_OpenSession(*args): return _PyKCS11.CPKCS11Lib_C_OpenSession(*args)
    def C_CloseSession(*args): return _PyKCS11.CPKCS11Lib_C_CloseSession(*args)
    def C_CloseAllSessions(*args): return _PyKCS11.CPKCS11Lib_C_CloseAllSessions(*args)
    def C_GetSessionInfo(*args): return _PyKCS11.CPKCS11Lib_C_GetSessionInfo(*args)
    def C_Login(*args): return _PyKCS11.CPKCS11Lib_C_Login(*args)
    def C_Logout(*args): return _PyKCS11.CPKCS11Lib_C_Logout(*args)
    def C_CreateObject(*args): return _PyKCS11.CPKCS11Lib_C_CreateObject(*args)
    def C_DestroyObject(*args): return _PyKCS11.CPKCS11Lib_C_DestroyObject(*args)
    def C_GetObjectSize(*args): return _PyKCS11.CPKCS11Lib_C_GetObjectSize(*args)
    def C_GetAttributeValue(*args): return _PyKCS11.CPKCS11Lib_C_GetAttributeValue(*args)
    def C_SetAttributeValue(*args): return _PyKCS11.CPKCS11Lib_C_SetAttributeValue(*args)
    def C_FindObjectsInit(*args): return _PyKCS11.CPKCS11Lib_C_FindObjectsInit(*args)
    def C_FindObjects(*args): return _PyKCS11.CPKCS11Lib_C_FindObjects(*args)
    def C_FindObjectsFinal(*args): return _PyKCS11.CPKCS11Lib_C_FindObjectsFinal(*args)
    def C_EncryptInit(*args): return _PyKCS11.CPKCS11Lib_C_EncryptInit(*args)
    def C_Encrypt(*args): return _PyKCS11.CPKCS11Lib_C_Encrypt(*args)
    def C_EncryptUpdate(*args): return _PyKCS11.CPKCS11Lib_C_EncryptUpdate(*args)
    def C_EncryptFinal(*args): return _PyKCS11.CPKCS11Lib_C_EncryptFinal(*args)
    def C_DecryptInit(*args): return _PyKCS11.CPKCS11Lib_C_DecryptInit(*args)
    def C_Decrypt(*args): return _PyKCS11.CPKCS11Lib_C_Decrypt(*args)
    def C_DecryptUpdate(*args): return _PyKCS11.CPKCS11Lib_C_DecryptUpdate(*args)
    def C_DecryptFinal(*args): return _PyKCS11.CPKCS11Lib_C_DecryptFinal(*args)
    def C_DigestInit(*args): return _PyKCS11.CPKCS11Lib_C_DigestInit(*args)
    def C_Digest(*args): return _PyKCS11.CPKCS11Lib_C_Digest(*args)
    def C_DigestUpdate(*args): return _PyKCS11.CPKCS11Lib_C_DigestUpdate(*args)
    def C_DigestKey(*args): return _PyKCS11.CPKCS11Lib_C_DigestKey(*args)
    def C_DigestFinal(*args): return _PyKCS11.CPKCS11Lib_C_DigestFinal(*args)
    def C_SignInit(*args): return _PyKCS11.CPKCS11Lib_C_SignInit(*args)
    def C_Sign(*args): return _PyKCS11.CPKCS11Lib_C_Sign(*args)
    def C_SignUpdate(*args): return _PyKCS11.CPKCS11Lib_C_SignUpdate(*args)
    def C_SignFinal(*args): return _PyKCS11.CPKCS11Lib_C_SignFinal(*args)
    def C_VerifyInit(*args): return _PyKCS11.CPKCS11Lib_C_VerifyInit(*args)
    def C_Verify(*args): return _PyKCS11.CPKCS11Lib_C_Verify(*args)
    def C_VerifyUpdate(*args): return _PyKCS11.CPKCS11Lib_C_VerifyUpdate(*args)
    def C_VerifyFinal(*args): return _PyKCS11.CPKCS11Lib_C_VerifyFinal(*args)
    def C_GenerateKey(*args): return _PyKCS11.CPKCS11Lib_C_GenerateKey(*args)
    def C_GenerateKeyPair(*args): return _PyKCS11.CPKCS11Lib_C_GenerateKeyPair(*args)
    def C_WrapKey(*args): return _PyKCS11.CPKCS11Lib_C_WrapKey(*args)
    def C_UnwrapKey(*args): return _PyKCS11.CPKCS11Lib_C_UnwrapKey(*args)
    def C_SeedRandom(*args): return _PyKCS11.CPKCS11Lib_C_SeedRandom(*args)
    def C_GenerateRandom(*args): return _PyKCS11.CPKCS11Lib_C_GenerateRandom(*args)
    def C_WaitForSlotEvent(*args): return _PyKCS11.CPKCS11Lib_C_WaitForSlotEvent(*args)

class CPKCS11LibPtr(CPKCS11Lib):
    def __init__(self, this):
        _swig_setattr(self, CPKCS11Lib, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, CPKCS11Lib, 'thisown', 0)
        _swig_setattr(self, CPKCS11Lib,self.__class__,CPKCS11Lib)
_PyKCS11.CPKCS11Lib_swigregister(CPKCS11LibPtr)

class CK_ATTRIBUTE_SMART(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, CK_ATTRIBUTE_SMART, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, CK_ATTRIBUTE_SMART, name)
    def __repr__(self):
        return "<C CK_ATTRIBUTE_SMART instance at %s>" % (self.this,)
    def Reset(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_Reset(*args)
    def ResetValue(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_ResetValue(*args)
    def Reserve(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_Reserve(*args)
    def GetType(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_GetType(*args)
    def SetType(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_SetType(*args)
    def GetLen(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_GetLen(*args)
    def IsString(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_IsString(*args)
    def IsBool(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_IsBool(*args)
    def IsNum(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_IsNum(*args)
    def IsBin(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_IsBin(*args)
    def GetString(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_GetString(*args)
    def SetString(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_SetString(*args)
    def GetNum(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_GetNum(*args)
    def SetNum(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_SetNum(*args)
    def GetBool(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_GetBool(*args)
    def SetBool(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_SetBool(*args)
    def GetBin(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_GetBin(*args)
    def SetBin(*args): return _PyKCS11.CK_ATTRIBUTE_SMART_SetBin(*args)
    def __init__(self, *args):
        _swig_setattr(self, CK_ATTRIBUTE_SMART, 'this', _PyKCS11.new_CK_ATTRIBUTE_SMART(*args))
        _swig_setattr(self, CK_ATTRIBUTE_SMART, 'thisown', 1)
    def __del__(self, destroy=_PyKCS11.delete_CK_ATTRIBUTE_SMART):
        try:
            if self.thisown: destroy(self)
        except: pass

class CK_ATTRIBUTE_SMARTPtr(CK_ATTRIBUTE_SMART):
    def __init__(self, this):
        _swig_setattr(self, CK_ATTRIBUTE_SMART, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, CK_ATTRIBUTE_SMART, 'thisown', 0)
        _swig_setattr(self, CK_ATTRIBUTE_SMART,self.__class__,CK_ATTRIBUTE_SMART)
_PyKCS11.CK_ATTRIBUTE_SMART_swigregister(CK_ATTRIBUTE_SMARTPtr)


