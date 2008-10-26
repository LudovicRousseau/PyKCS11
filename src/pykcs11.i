//   Copyright (C) 2004 Midori (midori -- a-t -- paipai dot net)
//
// This file is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.

%module LowLevel
%{

#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include "opensc/pkcs11.h"

#ifdef WIN32
#pragma warning(disable: 4800 4244)
#endif

#include <vector>
#include "pykcs11string.h"
#include "ck_attribute_smart.h"
#include "pkcs11lib.h"

using namespace std;
%}


%inline
%{
	using namespace std;
%}

%include cdata.i
%include cpointer.i
%include carrays.i
%include typemaps.i
%include std_vector.i

%template(ckintlist) vector<long>;
%template(ckbytelist) vector<unsigned char>;
%template(ckattrlist) vector<CK_ATTRIBUTE_SMART>;
%template(ckobjlist) vector<CK_OBJECT_HANDLE>;

%pointer_class(unsigned long, CK_SESSION_HANDLE);
%pointer_class(unsigned long, CK_OBJECT_HANDLE);
%array_class(char,byteArray);

#if SWIGPYTHON
%typemap(out) PyKCS11String {
   $result = PyString_FromStringAndSize((const char*)($1.m_str.c_str()),(int)($1.m_str.size()));
}

%typemap(out) CK_RV {
   $result = PyInt_FromLong((long)$1);
}

#else
#endif


typedef struct CK_VERSION {
%immutable;
  unsigned char       major;
  unsigned char       minor;
%mutable;
} CK_VERSION;


typedef struct CK_INFO {
%immutable;
  CK_VERSION    cryptokiVersion;
  unsigned char   manufacturerID[32];
  unsigned long      flags;
  unsigned char   libraryDescription[32];
  CK_VERSION    libraryVersion;
%mutable;
} CK_INFO;

%extend CK_INFO
{
	PyKCS11String GetManufacturerID()
	{
		return PyKCS11String(self->manufacturerID, sizeof(self->manufacturerID));
	}
	PyKCS11String GetLibraryDescription()
	{
		return PyKCS11String(self->libraryDescription, sizeof(self->libraryDescription));
	}
	PyKCS11String GetLibraryVersion()
	{
		char szVal[10];
		sprintf(szVal, "%d.%d", self->libraryVersion.major, self->libraryVersion.minor);
		return PyKCS11String(szVal);
	}
};

typedef struct CK_SLOT_INFO {
%immutable;
  //unsigned char   slotDescription[64];
  //unsigned char   manufacturerID[32];
  unsigned long      flags;
  CK_VERSION    hardwareVersion;
  CK_VERSION    firmwareVersion;
%mutable;
} CK_SLOT_INFO;

%extend CK_SLOT_INFO
{
	PyKCS11String GetManufacturerID()
	{
		return PyKCS11String(self->manufacturerID, sizeof(self->manufacturerID));
	}
	PyKCS11String GetSlotDescription()
	{
		return PyKCS11String(self->slotDescription, sizeof(self->slotDescription));
	}
	PyKCS11String GetHardwareVersion()
	{
		char szVal[10];
		sprintf(szVal, "%d.%02d", self->hardwareVersion.major, self->hardwareVersion.minor);
		return PyKCS11String(szVal);
	}
	PyKCS11String GetFirmwareVersion()
	{
		char szVal[10];
		sprintf(szVal, "%d.%02d", self->firmwareVersion.major, self->firmwareVersion.minor);
		return PyKCS11String(szVal);
	}
};

typedef struct CK_TOKEN_INFO {
%immutable;
  //unsigned char   label[32];
  //unsigned char   manufacturerID[32];
  //unsigned char   model[16];
  //unsigned char       serialNumber[16];
  unsigned long      flags;
  unsigned long      ulMaxSessionCount;
  unsigned long      ulSessionCount;
  unsigned long      ulMaxRwSessionCount;
  unsigned long      ulRwSessionCount;
  unsigned long      ulMaxPinLen;
  unsigned long      ulMinPinLen;
  unsigned long      ulTotalPublicMemory;
  unsigned long      ulFreePublicMemory;
  unsigned long      ulTotalPrivateMemory;
  unsigned long      ulFreePrivateMemory;
  CK_VERSION    hardwareVersion;
  CK_VERSION    firmwareVersion;
  //unsigned char       utcTime[16];
%mutable;
} CK_TOKEN_INFO;

%extend CK_TOKEN_INFO
{
	PyKCS11String GetLabel()
	{
		return PyKCS11String(self->label, sizeof(self->label));
	}
	PyKCS11String GetManufacturerID()
	{
		return PyKCS11String(self->manufacturerID, sizeof(self->manufacturerID));
	}
	PyKCS11String GetModel()
	{
		return PyKCS11String(self->model, sizeof(self->model));
	}
	PyKCS11String GetSerialNumber()
	{
		return PyKCS11String(self->serialNumber, sizeof(self->serialNumber));
	}
	PyKCS11String GetFirmwareVersion()
	{
		char szVal[10];
		sprintf(szVal, "%d.%02d", self->firmwareVersion.major, self->firmwareVersion.minor);
		return PyKCS11String(szVal);
	}
	PyKCS11String GetUtcTime()
	{
		return PyKCS11String(self->utcTime, sizeof(self->utcTime));
	}
};

typedef struct CK_SESSION_INFO {
%immutable;
  unsigned long    slotID;
  unsigned long      state;
  unsigned long      flags;
  unsigned long      ulDeviceError;
%mutable;
} CK_SESSION_INFO;


typedef struct CK_DATE{
 //unsigned char       year[4];
 //unsigned char       month[2];
 // unsigned char       day[2];
} CK_DATE;

%extend CK_DATE
{
	PyKCS11String GetYear()
	{
		char szVal[10];
		memcpy(szVal, self->year, sizeof(self->year) );
		return PyKCS11String(szVal);
	}
	PyKCS11String GetMonth()
	{
		char szVal[10];
		memcpy(szVal, self->month, sizeof(self->month) );
		return PyKCS11String(szVal);
	}
	PyKCS11String GetDay()
	{
		char szVal[10];
		memcpy(szVal, self->day, sizeof(self->day) );
		return PyKCS11String(szVal);
	}
};

typedef struct CK_MECHANISM {
  unsigned long mechanism;
  void*       pParameter;
  unsigned long          ulParameterLen;
} CK_MECHANISM;

%extend CK_MECHANISM
{
	CK_MECHANISM()
	{
		CK_MECHANISM* m = new CK_MECHANISM();
		m->ulParameterLen = m->mechanism = 0; m->pParameter = NULL;
		return m;
	}
};

typedef struct CK_MECHANISM_INFO {
%immutable;
    unsigned long    ulMinKeySize;
    unsigned long    ulMaxKeySize;
    unsigned long    flags;
%mutable;    
} CK_MECHANISM_INFO;
typedef unsigned long CK_RV;

#define FALSE 0
#define TRUE !(FALSE)

#define CK_TRUE 1
#define CK_FALSE 0
#define CK_UNAVAILABLE_INFORMATION (~0UL)
#define CK_EFFECTIVELY_INFINITE    0
#define CK_INVALID_HANDLE 0

#define CKN_SURRENDER       0

#define CKF_TOKEN_PRESENT     0x00000001  
#define CKF_REMOVABLE_DEVICE  0x00000002  
#define CKF_HW_SLOT           0x00000004  
#define CKF_RNG                     0x00000001  
#define CKF_WRITE_PROTECTED         0x00000002 
#define CKF_LOGIN_REQUIRED          0x00000004  
#define CKF_USER_PIN_INITIALIZED    0x00000008  
#define CKF_RESTORE_KEY_NOT_NEEDED  0x00000020
#define CKF_CLOCK_ON_TOKEN          0x00000040
#define CKF_PROTECTED_AUTHENTICATION_PATH 0x00000100
#define CKF_DUAL_CRYPTO_OPERATIONS  0x00000200
#define CKF_TOKEN_INITIALIZED       0x00000400
#define CKF_SECONDARY_AUTHENTICATION  0x00000800
#define CKF_USER_PIN_COUNT_LOW       0x00010000
#define CKF_USER_PIN_FINAL_TRY       0x00020000
#define CKF_USER_PIN_LOCKED          0x00040000
#define CKF_USER_PIN_TO_BE_CHANGED   0x00080000
#define CKF_SO_PIN_COUNT_LOW         0x00100000
#define CKF_SO_PIN_FINAL_TRY         0x00200000
#define CKF_SO_PIN_LOCKED            0x00400000
#define CKF_SO_PIN_TO_BE_CHANGED     0x00800000

#define CKU_SO    0
#define CKU_USER  1

#define CKS_RO_PUBLIC_SESSION  0
#define CKS_RO_USER_FUNCTIONS  1
#define CKS_RW_PUBLIC_SESSION  2
#define CKS_RW_USER_FUNCTIONS  3
#define CKS_RW_SO_FUNCTIONS    4

#define CKF_RW_SESSION          0x00000002  
#define CKF_SERIAL_SESSION      0x00000004 

#define CKO_DATA              0x00000000
#define CKO_CERTIFICATE       0x00000001
#define CKO_PUBLIC_KEY        0x00000002
#define CKO_PRIVATE_KEY       0x00000003
#define CKO_SECRET_KEY        0x00000004
#define CKO_HW_FEATURE        0x00000005
#define CKO_DOMAIN_PARAMETERS 0x00000006
#define CKO_MECHANISM         0x00000007
#define CKO_VENDOR_DEFINED    0x80000000

#define CKH_MONOTONIC_COUNTER  0x00000001
#define CKH_CLOCK           0x00000002
#define CKH_VENDOR_DEFINED  0x80000000

#define CKK_RSA             0x00000000
#define CKK_DSA             0x00000001
#define CKK_DH              0x00000002
#define CKK_ECDSA           0x00000003
#define CKK_EC              0x00000003
#define CKK_X9_42_DH        0x00000004
#define CKK_KEA             0x00000005
#define CKK_GENERIC_SECRET  0x00000010
#define CKK_RC2             0x00000011
#define CKK_RC4             0x00000012
#define CKK_DES             0x00000013
#define CKK_DES2            0x00000014
#define CKK_DES3            0x00000015
#define CKK_CAST            0x00000016
#define CKK_CAST3           0x00000017
#define CKK_CAST5           0x00000018
#define CKK_CAST128         0x00000018
#define CKK_RC5             0x00000019
#define CKK_IDEA            0x0000001A
#define CKK_SKIPJACK        0x0000001B
#define CKK_BATON           0x0000001C
#define CKK_JUNIPER         0x0000001D
#define CKK_CDMF            0x0000001E
#define CKK_AES             0x0000001F
#define CKK_BLOWFISH        0x00000020
#define CKK_TWOFISH         0x00000021
#define CKK_VENDOR_DEFINED  0x80000000

#define CKC_X_509           0x00000000
#define CKC_X_509_ATTR_CERT 0x00000001
#define CKC_WTLS            0x00000002
#define CKC_VENDOR_DEFINED  0x80000000

#define CKA_CLASS              0x00000000
#define CKA_TOKEN              0x00000001
#define CKA_PRIVATE            0x00000002
#define CKA_LABEL              0x00000003
#define CKA_APPLICATION        0x00000010
#define CKA_VALUE              0x00000011
#define CKA_OBJECT_ID          0x00000012
#define CKA_CERTIFICATE_TYPE   0x00000080
#define CKA_ISSUER             0x00000081
#define CKA_SERIAL_NUMBER      0x00000082
#define CKA_AC_ISSUER          0x00000083
#define CKA_OWNER              0x00000084
#define CKA_ATTR_TYPES         0x00000085
#define CKA_TRUSTED            0x00000086
#define CKA_KEY_TYPE           0x00000100
#define CKA_SUBJECT            0x00000101
#define CKA_ID                 0x00000102
#define CKA_SENSITIVE          0x00000103
#define CKA_ENCRYPT            0x00000104
#define CKA_DECRYPT            0x00000105
#define CKA_WRAP               0x00000106
#define CKA_UNWRAP             0x00000107
#define CKA_SIGN               0x00000108
#define CKA_SIGN_RECOVER       0x00000109
#define CKA_VERIFY             0x0000010A
#define CKA_VERIFY_RECOVER     0x0000010B
#define CKA_DERIVE             0x0000010C
#define CKA_START_DATE         0x00000110
#define CKA_END_DATE           0x00000111
#define CKA_MODULUS            0x00000120
#define CKA_MODULUS_BITS       0x00000121
#define CKA_PUBLIC_EXPONENT    0x00000122
#define CKA_PRIVATE_EXPONENT   0x00000123
#define CKA_PRIME_1            0x00000124
#define CKA_PRIME_2            0x00000125
#define CKA_EXPONENT_1         0x00000126
#define CKA_EXPONENT_2         0x00000127
#define CKA_COEFFICIENT        0x00000128
#define CKA_PRIME              0x00000130
#define CKA_SUBPRIME           0x00000131
#define CKA_BASE               0x00000132
#define CKA_PRIME_BITS         0x00000133
#define CKA_SUBPRIME_BITS      0x00000134 
#define CKA_SUB_PRIME_BITS     CKA_SUBPRIME_BITS 
#define CKA_VALUE_BITS         0x00000160
#define CKA_VALUE_LEN          0x00000161
#define CKA_EXTRACTABLE        0x00000162
#define CKA_LOCAL              0x00000163
#define CKA_NEVER_EXTRACTABLE  0x00000164
#define CKA_ALWAYS_SENSITIVE   0x00000165
#define CKA_KEY_GEN_MECHANISM  0x00000166
#define CKA_MODIFIABLE         0x00000170
#define CKA_ECDSA_PARAMS       0x00000180
#define CKA_EC_PARAMS          0x00000180
#define CKA_EC_POINT           0x00000181
#define CKA_SECONDARY_AUTH     0x00000200
#define CKA_AUTH_PIN_FLAGS     0x00000201
#define CKA_HW_FEATURE_TYPE    0x00000300
#define CKA_RESET_ON_INIT      0x00000301
#define CKA_HAS_RESET          0x00000302
#define CKA_VENDOR_DEFINED     0x80000000

#define CKM_RSA_PKCS_KEY_PAIR_GEN      0x00000000
#define CKM_RSA_PKCS                   0x00000001
#define CKM_RSA_9796                   0x00000002
#define CKM_RSA_X_509                  0x00000003
#define CKM_MD2_RSA_PKCS               0x00000004
#define CKM_MD5_RSA_PKCS               0x00000005
#define CKM_SHA1_RSA_PKCS              0x00000006
#define CKM_RIPEMD128_RSA_PKCS         0x00000007
#define CKM_RIPEMD160_RSA_PKCS         0x00000008
#define CKM_RSA_PKCS_OAEP              0x00000009
#define CKM_RSA_X9_31_KEY_PAIR_GEN     0x0000000A
#define CKM_RSA_X9_31                  0x0000000B
#define CKM_SHA1_RSA_X9_31             0x0000000C
#define CKM_RSA_PKCS_PSS               0x0000000D
#define CKM_SHA1_RSA_PKCS_PSS          0x0000000E
#define CKM_DSA_KEY_PAIR_GEN           0x00000010
#define CKM_DSA                        0x00000011
#define CKM_DSA_SHA1                   0x00000012
#define CKM_DH_PKCS_KEY_PAIR_GEN       0x00000020
#define CKM_DH_PKCS_DERIVE             0x00000021
#define CKM_X9_42_DH_KEY_PAIR_GEN      0x00000030
#define CKM_X9_42_DH_DERIVE            0x00000031
#define CKM_X9_42_DH_HYBRID_DERIVE     0x00000032
#define CKM_X9_42_MQV_DERIVE           0x00000033
#define CKM_SHA256_RSA_PKCS            0x00000040
#define CKM_SHA384_RSA_PKCS            0x00000041
#define CKM_SHA512_RSA_PKCS            0x00000042
#define CKM_SHA256_RSA_PKCS_PSS        0x00000043
#define CKM_SHA384_RSA_PKCS_PSS        0x00000044
#define CKM_SHA512_RSA_PKCS_PSS        0x00000045
#define CKM_RC2_KEY_GEN                0x00000100
#define CKM_RC2_ECB                    0x00000101
#define CKM_RC2_CBC                    0x00000102
#define CKM_RC2_MAC                    0x00000103
#define CKM_RC2_MAC_GENERAL            0x00000104
#define CKM_RC2_CBC_PAD                0x00000105
#define CKM_RC4_KEY_GEN                0x00000110
#define CKM_RC4                        0x00000111
#define CKM_DES_KEY_GEN                0x00000120
#define CKM_DES_ECB                    0x00000121
#define CKM_DES_CBC                    0x00000122
#define CKM_DES_MAC                    0x00000123
#define CKM_DES_MAC_GENERAL            0x00000124
#define CKM_DES_CBC_PAD                0x00000125
#define CKM_DES2_KEY_GEN               0x00000130
#define CKM_DES3_KEY_GEN               0x00000131
#define CKM_DES3_ECB                   0x00000132
#define CKM_DES3_CBC                   0x00000133
#define CKM_DES3_MAC                   0x00000134
#define CKM_DES3_MAC_GENERAL           0x00000135
#define CKM_DES3_CBC_PAD               0x00000136
#define CKM_CDMF_KEY_GEN               0x00000140
#define CKM_CDMF_ECB                   0x00000141
#define CKM_CDMF_CBC                   0x00000142
#define CKM_CDMF_MAC                   0x00000143
#define CKM_CDMF_MAC_GENERAL           0x00000144
#define CKM_CDMF_CBC_PAD               0x00000145
#define CKM_DES_OFB64                  0x00000150
#define CKM_DES_OFB8                   0x00000151
#define CKM_DES_CFB64                  0x00000152
#define CKM_DES_CFB8                   0x00000153
#define CKM_MD2                        0x00000200
#define CKM_MD2_HMAC                   0x00000201
#define CKM_MD2_HMAC_GENERAL           0x00000202
#define CKM_MD5                        0x00000210
#define CKM_MD5_HMAC                   0x00000211
#define CKM_MD5_HMAC_GENERAL           0x00000212
#define CKM_SHA_1                      0x00000220
#define CKM_SHA_1_HMAC                 0x00000221
#define CKM_SHA_1_HMAC_GENERAL         0x00000222
#define CKM_RIPEMD128                  0x00000230
#define CKM_RIPEMD128_HMAC             0x00000231
#define CKM_RIPEMD128_HMAC_GENERAL     0x00000232
#define CKM_RIPEMD160                  0x00000240
#define CKM_RIPEMD160_HMAC             0x00000241
#define CKM_RIPEMD160_HMAC_GENERAL     0x00000242
#define CKM_SHA256                     0x00000250
#define CKM_SHA256_HMAC                0x00000251
#define CKM_SHA256_HMAC_GENERAL        0x00000252
#define CKM_SHA384                     0x00000260
#define CKM_SHA384_HMAC                0x00000261
#define CKM_SHA384_HMAC_GENERAL        0x00000262
#define CKM_SHA512                     0x00000270
#define CKM_SHA512_HMAC                0x00000271
#define CKM_SHA512_HMAC_GENERAL        0x00000272
#define CKM_CAST_KEY_GEN               0x00000300
#define CKM_CAST_ECB                   0x00000301
#define CKM_CAST_CBC                   0x00000302
#define CKM_CAST_MAC                   0x00000303
#define CKM_CAST_MAC_GENERAL           0x00000304
#define CKM_CAST_CBC_PAD               0x00000305
#define CKM_CAST3_KEY_GEN              0x00000310
#define CKM_CAST3_ECB                  0x00000311
#define CKM_CAST3_CBC                  0x00000312
#define CKM_CAST3_MAC                  0x00000313
#define CKM_CAST3_MAC_GENERAL          0x00000314
#define CKM_CAST3_CBC_PAD              0x00000315
#define CKM_CAST5_KEY_GEN              0x00000320
#define CKM_CAST128_KEY_GEN            0x00000320
#define CKM_CAST5_ECB                  0x00000321
#define CKM_CAST128_ECB                0x00000321
#define CKM_CAST5_CBC                  0x00000322
#define CKM_CAST128_CBC                0x00000322
#define CKM_CAST5_MAC                  0x00000323
#define CKM_CAST128_MAC                0x00000323
#define CKM_CAST5_MAC_GENERAL          0x00000324
#define CKM_CAST128_MAC_GENERAL        0x00000324
#define CKM_CAST5_CBC_PAD              0x00000325
#define CKM_CAST128_CBC_PAD            0x00000325
#define CKM_RC5_KEY_GEN                0x00000330
#define CKM_RC5_ECB                    0x00000331
#define CKM_RC5_CBC                    0x00000332
#define CKM_RC5_MAC                    0x00000333
#define CKM_RC5_MAC_GENERAL            0x00000334
#define CKM_RC5_CBC_PAD                0x00000335
#define CKM_IDEA_KEY_GEN               0x00000340
#define CKM_IDEA_ECB                   0x00000341
#define CKM_IDEA_CBC                   0x00000342
#define CKM_IDEA_MAC                   0x00000343
#define CKM_IDEA_MAC_GENERAL           0x00000344
#define CKM_IDEA_CBC_PAD               0x00000345
#define CKM_GENERIC_SECRET_KEY_GEN     0x00000350
#define CKM_CONCATENATE_BASE_AND_KEY   0x00000360
#define CKM_CONCATENATE_BASE_AND_DATA  0x00000362
#define CKM_CONCATENATE_DATA_AND_BASE  0x00000363
#define CKM_XOR_BASE_AND_DATA          0x00000364
#define CKM_EXTRACT_KEY_FROM_KEY       0x00000365
#define CKM_SSL3_PRE_MASTER_KEY_GEN    0x00000370
#define CKM_SSL3_MASTER_KEY_DERIVE     0x00000371
#define CKM_SSL3_KEY_AND_MAC_DERIVE    0x00000372
#define CKM_SSL3_MASTER_KEY_DERIVE_DH  0x00000373
#define CKM_TLS_PRE_MASTER_KEY_GEN     0x00000374
#define CKM_TLS_MASTER_KEY_DERIVE      0x00000375
#define CKM_TLS_KEY_AND_MAC_DERIVE     0x00000376
#define CKM_TLS_MASTER_KEY_DERIVE_DH   0x00000377
#define CKM_TLS_PRF                    0x00000378
#define CKM_SSL3_MD5_MAC               0x00000380
#define CKM_SSL3_SHA1_MAC              0x00000381
#define CKM_MD5_KEY_DERIVATION         0x00000390
#define CKM_MD2_KEY_DERIVATION         0x00000391
#define CKM_SHA1_KEY_DERIVATION        0x00000392
#define CKM_SHA256_KEY_DERIVATION      0x00000393
#define CKM_SHA384_KEY_DERIVATION      0x00000394
#define CKM_SHA512_KEY_DERIVATION      0x00000395
#define CKM_PBE_MD2_DES_CBC            0x000003A0
#define CKM_PBE_MD5_DES_CBC            0x000003A1
#define CKM_PBE_MD5_CAST_CBC           0x000003A2
#define CKM_PBE_MD5_CAST3_CBC          0x000003A3
#define CKM_PBE_MD5_CAST5_CBC          0x000003A4
#define CKM_PBE_MD5_CAST128_CBC        0x000003A4
#define CKM_PBE_SHA1_CAST5_CBC         0x000003A5
#define CKM_PBE_SHA1_CAST128_CBC       0x000003A5
#define CKM_PBE_SHA1_RC4_128           0x000003A6
#define CKM_PBE_SHA1_RC4_40            0x000003A7
#define CKM_PBE_SHA1_DES3_EDE_CBC      0x000003A8
#define CKM_PBE_SHA1_DES2_EDE_CBC      0x000003A9
#define CKM_PBE_SHA1_RC2_128_CBC       0x000003AA
#define CKM_PBE_SHA1_RC2_40_CBC        0x000003AB
#define CKM_PKCS5_PBKD2                0x000003B0
#define CKM_PBA_SHA1_WITH_SHA1_HMAC    0x000003C0
#define CKM_WTLS_PRE_MASTER_KEY_GEN         0x000003D0
#define CKM_WTLS_MASTER_KEY_DERIVE          0x000003D1
#define CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC   0x000003D2
#define CKM_WTLS_PRF                        0x000003D3
#define CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE  0x000003D4
#define CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE  0x000003D5
#define CKM_KEY_WRAP_LYNKS             0x00000400
#define CKM_KEY_WRAP_SET_OAEP          0x00000401
#define CKM_CMS_SIG                    0x00000500
#define CKM_SKIPJACK_KEY_GEN           0x00001000
#define CKM_SKIPJACK_ECB64             0x00001001
#define CKM_SKIPJACK_CBC64             0x00001002
#define CKM_SKIPJACK_OFB64             0x00001003
#define CKM_SKIPJACK_CFB64             0x00001004
#define CKM_SKIPJACK_CFB32             0x00001005
#define CKM_SKIPJACK_CFB16             0x00001006
#define CKM_SKIPJACK_CFB8              0x00001007
#define CKM_SKIPJACK_WRAP              0x00001008
#define CKM_SKIPJACK_PRIVATE_WRAP      0x00001009
#define CKM_SKIPJACK_RELAYX            0x0000100a
#define CKM_KEA_KEY_PAIR_GEN           0x00001010
#define CKM_KEA_KEY_DERIVE             0x00001011
#define CKM_FORTEZZA_TIMESTAMP         0x00001020
#define CKM_BATON_KEY_GEN              0x00001030
#define CKM_BATON_ECB128               0x00001031
#define CKM_BATON_ECB96                0x00001032
#define CKM_BATON_CBC128               0x00001033
#define CKM_BATON_COUNTER              0x00001034
#define CKM_BATON_SHUFFLE              0x00001035
#define CKM_BATON_WRAP                 0x00001036
#define CKM_ECDSA_KEY_PAIR_GEN         0x00001040
#define CKM_EC_KEY_PAIR_GEN            0x00001040
#define CKM_ECDSA                      0x00001041
#define CKM_ECDSA_SHA1                 0x00001042
#define CKM_ECDH1_DERIVE               0x00001050
#define CKM_ECDH1_COFACTOR_DERIVE      0x00001051
#define CKM_ECMQV_DERIVE               0x00001052
#define CKM_JUNIPER_KEY_GEN            0x00001060
#define CKM_JUNIPER_ECB128             0x00001061
#define CKM_JUNIPER_CBC128             0x00001062
#define CKM_JUNIPER_COUNTER            0x00001063
#define CKM_JUNIPER_SHUFFLE            0x00001064
#define CKM_JUNIPER_WRAP               0x00001065
#define CKM_FASTHASH                   0x00001070
#define CKM_AES_KEY_GEN                0x00001080
#define CKM_AES_ECB                    0x00001081
#define CKM_AES_CBC                    0x00001082
#define CKM_AES_MAC                    0x00001083
#define CKM_AES_MAC_GENERAL            0x00001084
#define CKM_AES_CBC_PAD                0x00001085
#define CKM_BLOWFISH_KEY_GEN           0x00001090
#define CKM_BLOWFISH_CBC               0x00001091
#define CKM_TWOFISH_KEY_GEN            0x00001092
#define CKM_TWOFISH_CBC                0x00001093
#define CKM_DES_ECB_ENCRYPT_DATA       0x00001100
#define CKM_DES_CBC_ENCRYPT_DATA       0x00001101
#define CKM_DES3_ECB_ENCRYPT_DATA      0x00001102
#define CKM_DES3_CBC_ENCRYPT_DATA      0x00001103
#define CKM_AES_ECB_ENCRYPT_DATA       0x00001104
#define CKM_AES_CBC_ENCRYPT_DATA       0x00001105
#define CKM_DSA_PARAMETER_GEN          0x00002000
#define CKM_DH_PKCS_PARAMETER_GEN      0x00002001
#define CKM_X9_42_DH_PARAMETER_GEN     0x00002002
#define CKM_VENDOR_DEFINED             0x80000000

#define CKF_HW                 0x00000001  
#define CKF_ENCRYPT            0x00000100
#define CKF_DECRYPT            0x00000200
#define CKF_DIGEST             0x00000400
#define CKF_SIGN               0x00000800
#define CKF_SIGN_RECOVER       0x00001000
#define CKF_VERIFY             0x00002000
#define CKF_VERIFY_RECOVER     0x00004000
#define CKF_GENERATE           0x00008000
#define CKF_GENERATE_KEY_PAIR  0x00010000
#define CKF_WRAP               0x00020000
#define CKF_UNWRAP             0x00040000
#define CKF_DERIVE             0x00080000
#define CKF_EC_F_P             0x00100000
#define CKF_EC_F_2M            0x00200000
#define CKF_EC_ECPARAMETERS    0x00400000
#define CKF_EC_NAMEDCURVE      0x00800000
#define CKF_EC_UNCOMPRESS      0x01000000
#define CKF_EC_COMPRESS        0x02000000
#define CKF_EXTENSION          0x80000000  

#define CKR_OK                                0x00000000
#define CKR_CANCEL                            0x00000001
#define CKR_HOST_MEMORY                       0x00000002
#define CKR_SLOT_ID_INVALID                   0x00000003
#define CKR_GENERAL_ERROR                     0x00000005
#define CKR_FUNCTION_FAILED                   0x00000006
#define CKR_ARGUMENTS_BAD                     0x00000007
#define CKR_NO_EVENT                          0x00000008
#define CKR_NEED_TO_CREATE_THREADS            0x00000009
#define CKR_CANT_LOCK                         0x0000000A
#define CKR_ATTRIBUTE_READ_ONLY               0x00000010
#define CKR_ATTRIBUTE_SENSITIVE               0x00000011
#define CKR_ATTRIBUTE_TYPE_INVALID            0x00000012
#define CKR_ATTRIBUTE_VALUE_INVALID           0x00000013
#define CKR_DATA_INVALID                      0x00000020
#define CKR_DATA_LEN_RANGE                    0x00000021
#define CKR_DEVICE_ERROR                      0x00000030
#define CKR_DEVICE_MEMORY                     0x00000031
#define CKR_DEVICE_REMOVED                    0x00000032
#define CKR_ENCRYPTED_DATA_INVALID            0x00000040
#define CKR_ENCRYPTED_DATA_LEN_RANGE          0x00000041
#define CKR_FUNCTION_CANCELED                 0x00000050
#define CKR_FUNCTION_NOT_PARALLEL             0x00000051
#define CKR_FUNCTION_NOT_SUPPORTED            0x00000054
#define CKR_KEY_HANDLE_INVALID                0x00000060
#define CKR_KEY_SIZE_RANGE                    0x00000062
#define CKR_KEY_TYPE_INCONSISTENT             0x00000063
#define CKR_KEY_NOT_NEEDED                    0x00000064
#define CKR_KEY_CHANGED                       0x00000065
#define CKR_KEY_NEEDED                        0x00000066
#define CKR_KEY_INDIGESTIBLE                  0x00000067
#define CKR_KEY_FUNCTION_NOT_PERMITTED        0x00000068
#define CKR_KEY_NOT_WRAPPABLE                 0x00000069
#define CKR_KEY_UNEXTRACTABLE                 0x0000006A
#define CKR_MECHANISM_INVALID                 0x00000070
#define CKR_MECHANISM_PARAM_INVALID           0x00000071
#define CKR_OBJECT_HANDLE_INVALID             0x00000082
#define CKR_OPERATION_ACTIVE                  0x00000090
#define CKR_OPERATION_NOT_INITIALIZED         0x00000091
#define CKR_PIN_INCORRECT                     0x000000A0
#define CKR_PIN_INVALID                       0x000000A1
#define CKR_PIN_LEN_RANGE                     0x000000A2
#define CKR_PIN_EXPIRED                       0x000000A3
#define CKR_PIN_LOCKED                        0x000000A4
#define CKR_SESSION_CLOSED                    0x000000B0
#define CKR_SESSION_COUNT                     0x000000B1
#define CKR_SESSION_HANDLE_INVALID            0x000000B3
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED    0x000000B4
#define CKR_SESSION_READ_ONLY                 0x000000B5
#define CKR_SESSION_EXISTS                    0x000000B6
#define CKR_SESSION_READ_ONLY_EXISTS          0x000000B7
#define CKR_SESSION_READ_WRITE_SO_EXISTS      0x000000B8
#define CKR_SIGNATURE_INVALID                 0x000000C0
#define CKR_SIGNATURE_LEN_RANGE               0x000000C1
#define CKR_TEMPLATE_INCOMPLETE               0x000000D0
#define CKR_TEMPLATE_INCONSISTENT             0x000000D1
#define CKR_TOKEN_NOT_PRESENT                 0x000000E0
#define CKR_TOKEN_NOT_RECOGNIZED              0x000000E1
#define CKR_TOKEN_WRITE_PROTECTED             0x000000E2
#define CKR_UNWRAPPING_KEY_HANDLE_INVALID     0x000000F0
#define CKR_UNWRAPPING_KEY_SIZE_RANGE         0x000000F1
#define CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  0x000000F2
#define CKR_USER_ALREADY_LOGGED_IN            0x00000100
#define CKR_USER_NOT_LOGGED_IN                0x00000101
#define CKR_USER_PIN_NOT_INITIALIZED          0x00000102
#define CKR_USER_TYPE_INVALID                 0x00000103
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN    0x00000104
#define CKR_USER_TOO_MANY_TYPES               0x00000105
#define CKR_WRAPPED_KEY_INVALID               0x00000110
#define CKR_WRAPPED_KEY_LEN_RANGE             0x00000112
#define CKR_WRAPPING_KEY_HANDLE_INVALID       0x00000113
#define CKR_WRAPPING_KEY_SIZE_RANGE           0x00000114
#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT    0x00000115
#define CKR_RANDOM_SEED_NOT_SUPPORTED         0x00000120
#define CKR_RANDOM_NO_RNG                     0x00000121
#define CKR_DOMAIN_PARAMS_INVALID             0x00000130
#define CKR_BUFFER_TOO_SMALL                  0x00000150
#define CKR_SAVED_STATE_INVALID               0x00000160
#define CKR_INFORMATION_SENSITIVE             0x00000170
#define CKR_STATE_UNSAVEABLE                  0x00000180
#define CKR_CRYPTOKI_NOT_INITIALIZED          0x00000190
#define CKR_CRYPTOKI_ALREADY_INITIALIZED      0x00000191
#define CKR_MUTEX_BAD                         0x000001A0
#define CKR_MUTEX_NOT_LOCKED                  0x000001A1
#define CKR_VENDOR_DEFINED                    0x80000000

#define CKF_LIBRARY_CANT_CREATE_OS_THREADS 0x00000001
#define CKF_OS_LOCKING_OK                  0x00000002
#define CKF_DONT_BLOCK     1

#define CKG_MGF1_SHA1         0x00000001

#define CKZ_DATA_SPECIFIED    0x00000001

#define CKD_NULL                 0x00000001
#define CKD_SHA1_KDF             0x00000002
#define CKD_NULL                 0x00000001
#define CKD_SHA1_KDF_ASN1        0x00000003
#define CKD_SHA1_KDF_CONCATENATE 0x00000004

#define CKP_PKCS5_PBKD2_HMAC_SHA1 0x00000001

#define CKZ_SALT_SPECIFIED        0x00000001


%include "pkcs11lib.h"


class CK_ATTRIBUTE_SMART
{
	public:
	void Reset();
	void ResetValue();
	void Reserve(long len);
	unsigned long GetType() const;
	void SetType(unsigned long attrType);
	int GetLen() const;

	bool IsString() const;
	bool IsBool() const;
	bool IsNum() const;
	bool IsBin() const;

	PyKCS11String GetString() const;
	void SetString(unsigned long attrType, const char* szValue);

	long GetNum() const;
	void SetNum(unsigned long attrType, unsigned long ulValue);

	bool GetBool() const;
	void SetBool(unsigned long attrType, bool bValue);

	vector<unsigned char> GetBin();
	void SetBin(unsigned long attrType, const vector<unsigned char>& pBuf);
};
