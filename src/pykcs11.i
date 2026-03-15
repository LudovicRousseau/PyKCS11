//   Copyright (C) 2004 Midori (midori -- a-t -- paipai dot net)
//   Copyright (C) 2015-2025 Ludovic Rousseau (ludovic.rousseau@free.fr)
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
%include typemaps.i
%include std_vector.i

%template(ckulonglist) vector<unsigned long>;
%template(ckbytelist) vector<unsigned char>;
%template(ckattrlist) vector<CK_ATTRIBUTE_SMART>;

%pointer_class(unsigned long, CK_SESSION_HANDLE);
%pointer_class(unsigned long, CK_OBJECT_HANDLE);

#if SWIGPYTHON
%typemap(out) PyKCS11String {
  #ifdef Py_USING_UNICODE
   $result = PyBytes_FromStringAndSize((const char*)($1.m_str.c_str()),(int)($1.m_str.size()));
  #else
   $result = PyUnicode_Decode((const char*)($1.m_str.c_str()),(int)($1.m_str.size()), "utf-8", "ignore");
  #endif
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
		snprintf(szVal, sizeof szVal, "%d.%d", self->libraryVersion.major, self->libraryVersion.minor);
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
		snprintf(szVal, sizeof szVal, "%d.%02d", self->hardwareVersion.major, self->hardwareVersion.minor);
		return PyKCS11String(szVal);
	}
    PyKCS11String GetFirmwareVersion()
	{
		char szVal[10];
		snprintf(szVal, sizeof szVal, "%d.%02d", self->firmwareVersion.major, self->firmwareVersion.minor);
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
		snprintf(szVal, sizeof szVal, "%d.%02d", self->firmwareVersion.major, self->firmwareVersion.minor);
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

%typemap(in) void* {
    vector<unsigned char> *vect;
    // If the value being set is of ckbytelist type:
    if (SWIG_IsOK(SWIG_ConvertPtr($input, (void **)&vect, $descriptor(vector<unsigned char> *), 0)))
    {
        // Get the data from the vector
        // Only set value if not null
        if (vect)
            arg2 = vect->data();
        else
            arg2 = NULL;
    }
    else
    {
        // If the value isn't a ckbytelist, then it must be a pointer to a mechanism parameter
        int res2 = -1;
        do { // Add mechanism parameters here
            res2 = SWIG_ConvertPtr($input, &arg2, $descriptor(CK_RSA_PKCS_OAEP_PARAMS*), 0);
            if( SWIG_IsOK( res2 ) )
                break;

            res2 = SWIG_ConvertPtr($input, &arg2, $descriptor(CK_RSA_PKCS_PSS_PARAMS*), 0);
            if( SWIG_IsOK( res2 ) )
                break;

            res2 = SWIG_ConvertPtr($input, &arg2, $descriptor(CK_GCM_PARAMS*), 0);
            if( SWIG_IsOK( res2 ) )
                break;

            res2 = SWIG_ConvertPtr($input, &arg2, $descriptor(CK_ECDH1_DERIVE_PARAMS*), 0);
            if( SWIG_IsOK( res2 ) )
                break;

            res2 = SWIG_ConvertPtr($input, &arg2, $descriptor(CK_AES_CTR_PARAMS*), 0);
            if( SWIG_IsOK( res2 ) )
                break;

            res2 = SWIG_ConvertPtr($input, &arg2, $descriptor(CK_KEY_DERIVATION_STRING_DATA*), 0);
            if( SWIG_IsOK( res2 ) )
                break;

            res2 = SWIG_ConvertPtr($input, &arg2, $descriptor(CK_EXTRACT_PARAMS*), 0);
            if( SWIG_IsOK( res2 ) )
                break;

            res2 = SWIG_ConvertPtr($input, &arg2, $descriptor(CK_EDDSA_PARAMS*), 0);
            if( SWIG_IsOK( res2 ) )
                break;

            res2 = SWIG_ConvertPtr($input, &arg2, $descriptor(CK_OBJECT_HANDLE*), 0);
            if( SWIG_IsOK( res2 ) )
                break;
        } while(0);

        if (!SWIG_IsOK(res2)) {
            SWIG_exception_fail(SWIG_ArgError(res2), "unsupported CK_MECHANISM Parameter type.");
        }
    }
}

// typemap for CK_BYTE_PTR (unsigned char*) mechanism parameters
%typemap(in) unsigned char* {
    vector<unsigned char> *vect;
    // If the value being set is of ckbytelist type:
    int res = SWIG_ConvertPtr($input, (void **)&vect, $descriptor(vector<unsigned char> *), 0);
    if (SWIG_IsOK(res))
    {
        // Get the data from the vector
        // Only set value if not null
        if (vect)
            arg2 = vect->data();
        else
            arg2 = NULL;
    }
    else
    {
        // If a mechanism parameter has a 'CK_BYTE_PTR' as a member, it must be represented as a ckbytelist
        SWIG_exception_fail(SWIG_ArgError(res), "CK_BYTE_PTR members of CK_* mechanism params must be represented as ckbytelist type");
    }
}

// typemap for CK_BYTE static arrays
%typemap(in) unsigned char[ANY](unsigned char out[$1_dim0]) {
    vector<unsigned char> *vect;
    // Expect a value of ckbytelist type:
    int res = SWIG_ConvertPtr($input, (void **)&vect, $descriptor(vector<unsigned char> *), 0);
    if (SWIG_IsOK(res))
    {
        if (vect->size() != $1_dim0)
        {
            SWIG_exception_fail(SWIG_ValueError, "Expected a ckbytelist with $1_dim0 elements");
        }

        for (size_t i = 0; i < $1_dim0; i++)
        {
            out[i] = (*vect)[i];
        }
    }
    else
    {
        // If a mechanism parameter has a CK_BYTE array as a member, it must be represented as a ckbytelist
        SWIG_exception_fail(SWIG_ArgError(res), "CK_BYTE arrays of CK_* mechanism params must be represented as ckbytelist type");
    }
    $1 = &out[0];
}

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

// For all complex mechanism parameters which has 'void *' as a member, it must a ckbytelist
%typemap(in) void* {
    vector<unsigned char> *vect;
    int res = SWIG_ConvertPtr($input, (void **)&vect, $descriptor(vector<unsigned char> *), 0);
    if (SWIG_IsOK(res))
    {
        // Get the data from the vector
        // Only set value if not null
        if (vect)
            arg2 = vect->data();
        else
            arg2 = NULL;
    }
    else
    {
        SWIG_exception_fail(SWIG_ArgError(res), "void * members of CK_* mechanism params must be represented as ckbytelist type");
    }
}

%constant int CK_OBJECT_HANDLE_LENGTH = sizeof(CK_OBJECT_HANDLE);

typedef struct CK_GCM_PARAMS {
    unsigned char * pIv;
    unsigned long ulIvLen;
    unsigned long ulIvBits;
    unsigned char * pAAD;
    unsigned long ulAADLen;
    unsigned long ulTagBits;
} CK_GCM_PARAMS;

%extend CK_GCM_PARAMS
{
    CK_GCM_PARAMS()
    {
        CK_GCM_PARAMS *p = new CK_GCM_PARAMS();
        p->pIv = p->pAAD = NULL;
        p->ulIvLen = p->ulIvBits = p->ulAADLen = p->ulTagBits = 0;
        return p;
    }
};

%constant int CK_GCM_PARAMS_LENGTH = sizeof(CK_GCM_PARAMS);

typedef struct CK_AES_CTR_PARAMS {
    unsigned long ulCounterBits;
    unsigned char cb[16];
} CK_AES_CTR_PARAMS;

%extend CK_AES_CTR_PARAMS
{
    CK_AES_CTR_PARAMS()
    {
        CK_AES_CTR_PARAMS *p = new CK_AES_CTR_PARAMS();
        p->ulCounterBits = 128;
        memset(p->cb, 0, sizeof(p->cb));
        return p;
    }
};

%constant int CK_AES_CTR_PARAMS_LENGTH = sizeof(CK_AES_CTR_PARAMS);

typedef struct CK_RSA_PKCS_OAEP_PARAMS {
  unsigned long hashAlg;
  unsigned long mgf;
  unsigned long source;
  void* pSourceData;
  unsigned long ulSourceDataLen;
} CK_RSA_PKCS_OAEP_PARAMS;

%extend CK_RSA_PKCS_OAEP_PARAMS
{
	CK_RSA_PKCS_OAEP_PARAMS()
	{
		CK_RSA_PKCS_OAEP_PARAMS* p = new CK_RSA_PKCS_OAEP_PARAMS();
		p->hashAlg = 0;
		p->mgf = 0;
		p->source = 0;
		p->pSourceData = NULL;
		p->ulSourceDataLen = 0;
    return p;
	}
};

%constant int CK_RSA_PKCS_OAEP_PARAMS_LENGTH = sizeof(CK_RSA_PKCS_OAEP_PARAMS);

typedef struct CK_RSA_PKCS_PSS_PARAMS {
    unsigned long hashAlg;
    unsigned long mgf;
    unsigned long sLen;
} CK_RSA_PKCS_PSS_PARAMS;

%extend CK_RSA_PKCS_PSS_PARAMS
{
    CK_RSA_PKCS_PSS_PARAMS()
    {
        CK_RSA_PKCS_PSS_PARAMS *p = new CK_RSA_PKCS_PSS_PARAMS();
        p->hashAlg = 0;
        p->mgf = 0;
        p->sLen = 0;
        return p;
    }
};

%constant int CK_RSA_PKCS_PSS_PARAMS_LENGTH = sizeof(CK_RSA_PKCS_PSS_PARAMS);

typedef struct CK_ECDH1_DERIVE_PARAMS {
    unsigned long kdf;
    unsigned long ulSharedDataLen;
    unsigned char* pSharedData;
    unsigned long ulPublicDataLen;
    unsigned char* pPublicData;
} CK_ECDH1_DERIVE_PARAMS;

%extend CK_ECDH1_DERIVE_PARAMS
{
	CK_ECDH1_DERIVE_PARAMS()
	{
		CK_ECDH1_DERIVE_PARAMS *p = new CK_ECDH1_DERIVE_PARAMS();
		p->kdf = CKD_NULL;
		p->pSharedData = NULL;
		p->ulSharedDataLen = 0;
		p->pPublicData = NULL;
		p->ulPublicDataLen = 0;

		return p;
	}
};

%constant int CK_ECDH1_DERIVE_PARAMS_LENGTH = sizeof(CK_ECDH1_DERIVE_PARAMS);

typedef struct CK_KEY_DERIVATION_STRING_DATA {
    unsigned char * pData;
    unsigned long ulLen;
} CK_KEY_DERIVATION_STRING_DATA;

%extend CK_KEY_DERIVATION_STRING_DATA
{
    CK_KEY_DERIVATION_STRING_DATA()
    {
        CK_KEY_DERIVATION_STRING_DATA *p = new CK_KEY_DERIVATION_STRING_DATA();
        p->ulLen = 0;
        p->pData = NULL;
        return p;
    }
};

%constant int CK_KEY_DERIVATION_STRING_DATA_LENGTH = sizeof(CK_KEY_DERIVATION_STRING_DATA);

%pointer_class(unsigned long, CK_EXTRACT_PARAMS);

%constant int CK_EXTRACT_PARAMS_LENGTH = sizeof(CK_EXTRACT_PARAMS);

typedef struct CK_EDDSA_PARAMS {
    unsigned char phFlag;
    unsigned long ulContextDataLen;
    unsigned char * pContextData;
} CK_EDDSA_PARAMS;

%extend CK_EDDSA_PARAMS
{
    CK_EDDSA_PARAMS()
    {
        CK_EDDSA_PARAMS *p = new CK_EDDSA_PARAMS();
        p->phFlag = 0;
        p->ulContextDataLen = 0;
        p->pContextData = NULL;
        return p;
    }
};

%constant int CK_EDDSA_PARAMS_LENGTH = sizeof(CK_EDDSA_PARAMS);

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

/* domain specific values and constants */

/* CK (certificate) */
#define CK_CERTIFICATE_CATEGORY_UNSPECIFIED 0UL
#define CK_CERTIFICATE_CATEGORY_TOKEN_USER 1UL
#define CK_CERTIFICATE_CATEGORY_AUTHORITY 2UL
#define CK_CERTIFICATE_CATEGORY_OTHER_ENTITY 3UL

/* CK (OTP) */
#define CK_OTP_VALUE 0UL
#define CK_OTP_PIN 1UL
#define CK_OTP_CHALLENGE 2UL
#define CK_OTP_TIME 3UL
#define CK_OTP_COUNTER 4UL
#define CK_OTP_FLAGS 5UL
#define CK_OTP_OUTPUT_LENGTH 6UL
#define CK_OTP_OUTPUT_FORMAT 7UL

/* CK (OTP format) */
#define CK_OTP_FORMAT_DECIMAL 0UL
#define CK_OTP_FORMAT_HEXADECIMAL 1UL
#define CK_OTP_FORMAT_ALPHANUMERIC 2UL
#define CK_OTP_FORMAT_BINARY 3UL

/* CK (OTP requirement) */
#define CK_OTP_PARAM_IGNORED 0UL
#define CK_OTP_PARAM_OPTIONAL 1UL
#define CK_OTP_PARAM_MANDATORY 2UL

/* CK (security) */
#define CK_SECURITY_DOMAIN_UNSPECIFIED 0UL
#define CK_SECURITY_DOMAIN_MANUFACTURER 1UL
#define CK_SECURITY_DOMAIN_OPERATOR 2UL
#define CK_SECURITY_DOMAIN_THIRD_PARTY 3UL

/* CK (SP800 KDF) */
#define CK_SP800_108_ITERATION_VARIABLE 0x00000001UL
#define CK_SP800_108_OPTIONAL_COUNTER 0x00000002UL
#define CK_SP800_108_COUNTER 0x00000002UL
#define CK_SP800_108_DKM_LENGTH 0x00000003UL
#define CK_SP800_108_BYTE_ARRAY 0x00000004UL
#define CK_SP800_108_KEY_HANDLE 0x00000005UL

/* CK (SP800 DKM) */
#define CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS 0x00000001UL
#define CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS 0x00000002UL

/* CKA */
#define CKA_CLASS 0x00000000UL
#define CKA_TOKEN 0x00000001UL
#define CKA_PRIVATE 0x00000002UL
#define CKA_LABEL 0x00000003UL
#define CKA_UNIQUE_ID 0x00000004UL
#define CKA_APPLICATION 0x00000010UL
#define CKA_VALUE 0x00000011UL
#define CKA_OBJECT_ID 0x00000012UL
#define CKA_CERTIFICATE_TYPE 0x00000080UL
#define CKA_ISSUER 0x00000081UL
#define CKA_SERIAL_NUMBER 0x00000082UL
#define CKA_AC_ISSUER 0x00000083UL
#define CKA_OWNER 0x00000084UL
#define CKA_ATTR_TYPES 0x00000085UL
#define CKA_TRUSTED 0x00000086UL
#define CKA_CERTIFICATE_CATEGORY 0x00000087UL
#define CKA_JAVA_MIDP_SECURITY_DOMAIN 0x00000088UL
#define CKA_URL 0x00000089UL
#define CKA_HASH_OF_SUBJECT_PUBLIC_KEY 0x0000008AUL
#define CKA_HASH_OF_ISSUER_PUBLIC_KEY 0x0000008BUL
#define CKA_NAME_HASH_ALGORITHM 0x0000008CUL
#define CKA_CHECK_VALUE 0x00000090UL
#define CKA_KEY_TYPE 0x00000100UL
#define CKA_SUBJECT 0x00000101UL
#define CKA_ID 0x00000102UL
#define CKA_SENSITIVE 0x00000103UL
#define CKA_ENCRYPT 0x00000104UL
#define CKA_DECRYPT 0x00000105UL
#define CKA_WRAP 0x00000106UL
#define CKA_UNWRAP 0x00000107UL
#define CKA_SIGN 0x00000108UL
#define CKA_SIGN_RECOVER 0x00000109UL
#define CKA_VERIFY 0x0000010AUL
#define CKA_VERIFY_RECOVER 0x0000010BUL
#define CKA_DERIVE 0x0000010CUL
#define CKA_START_DATE 0x00000110UL
#define CKA_END_DATE 0x00000111UL
#define CKA_MODULUS 0x00000120UL
#define CKA_MODULUS_BITS 0x00000121UL
#define CKA_PUBLIC_EXPONENT 0x00000122UL
#define CKA_PRIVATE_EXPONENT 0x00000123UL
#define CKA_PRIME_1 0x00000124UL
#define CKA_PRIME_2 0x00000125UL
#define CKA_EXPONENT_1 0x00000126UL
#define CKA_EXPONENT_2 0x00000127UL
#define CKA_COEFFICIENT 0x00000128UL
#define CKA_PUBLIC_KEY_INFO 0x00000129UL
#define CKA_PRIME 0x00000130UL
#define CKA_SUBPRIME 0x00000131UL
#define CKA_BASE 0x00000132UL
#define CKA_PRIME_BITS 0x00000133UL
#define CKA_SUBPRIME_BITS 0x00000134UL
#define CKA_SUB_PRIME_BITS 0x00000134UL
#define CKA_VALUE_BITS 0x00000160UL
#define CKA_VALUE_LEN 0x00000161UL
#define CKA_EXTRACTABLE 0x00000162UL
#define CKA_LOCAL 0x00000163UL
#define CKA_NEVER_EXTRACTABLE 0x00000164UL
#define CKA_ALWAYS_SENSITIVE 0x00000165UL
#define CKA_KEY_GEN_MECHANISM 0x00000166UL
#define CKA_MODIFIABLE 0x00000170UL
#define CKA_COPYABLE 0x00000171UL
#define CKA_DESTROYABLE 0x00000172UL
#define CKA_EC_PARAMS 0x00000180UL
#define CKA_EC_POINT 0x00000181UL
#define CKA_ALWAYS_AUTHENTICATE 0x00000202UL
#define CKA_WRAP_WITH_TRUSTED 0x00000210UL
#define CKA_OTP_FORMAT 0x00000220UL
#define CKA_OTP_LENGTH 0x00000221UL
#define CKA_OTP_TIME_INTERVAL 0x00000222UL
#define CKA_OTP_USER_FRIENDLY_MODE 0x00000223UL
#define CKA_OTP_CHALLENGE_REQUIREMENT 0x00000224UL
#define CKA_OTP_TIME_REQUIREMENT 0x00000225UL
#define CKA_OTP_COUNTER_REQUIREMENT 0x00000226UL
#define CKA_OTP_PIN_REQUIREMENT 0x00000227UL
#define CKA_OTP_COUNTER 0x0000022EUL
#define CKA_OTP_TIME 0x0000022FUL
#define CKA_OTP_USER_IDENTIFIER 0x0000022AUL
#define CKA_OTP_SERVICE_IDENTIFIER 0x0000022BUL
#define CKA_OTP_SERVICE_LOGO 0x0000022CUL
#define CKA_OTP_SERVICE_LOGO_TYPE 0x0000022DUL
#define CKA_GOSTR3410_PARAMS 0x00000250UL
#define CKA_GOSTR3411_PARAMS 0x00000251UL
#define CKA_GOST28147_PARAMS 0x00000252UL
#define CKA_HW_FEATURE_TYPE 0x00000300UL
#define CKA_RESET_ON_INIT 0x00000301UL
#define CKA_HAS_RESET 0x00000302UL
#define CKA_PIXEL_X 0x00000400UL
#define CKA_PIXEL_Y 0x00000401UL
#define CKA_RESOLUTION 0x00000402UL
#define CKA_CHAR_ROWS 0x00000403UL
#define CKA_CHAR_COLUMNS 0x00000404UL
#define CKA_COLOR 0x00000405UL
#define CKA_BITS_PER_PIXEL 0x00000406UL
#define CKA_CHAR_SETS 0x00000480UL
#define CKA_ENCODING_METHODS 0x00000481UL
#define CKA_MIME_TYPES 0x00000482UL
#define CKA_MECHANISM_TYPE 0x00000500UL
#define CKA_REQUIRED_CMS_ATTRIBUTES 0x00000501UL
#define CKA_DEFAULT_CMS_ATTRIBUTES 0x00000502UL
#define CKA_SUPPORTED_CMS_ATTRIBUTES 0x00000503UL
#define CKA_PROFILE_ID 0x00000601UL
#define CKA_X2RATCHET_BAG 0x00000602UL
#define CKA_X2RATCHET_BAGSIZE 0x00000603UL
#define CKA_X2RATCHET_BOBS1STMSG 0x00000604UL
#define CKA_X2RATCHET_CKR 0x00000605UL
#define CKA_X2RATCHET_CKS 0x00000606UL
#define CKA_X2RATCHET_DHP 0x00000607UL
#define CKA_X2RATCHET_DHR 0x00000608UL
#define CKA_X2RATCHET_DHS 0x00000609UL
#define CKA_X2RATCHET_HKR 0x0000060AUL
#define CKA_X2RATCHET_HKS 0x0000060BUL
#define CKA_X2RATCHET_ISALICE 0x0000060CUL
#define CKA_X2RATCHET_NHKR 0x0000060DUL
#define CKA_X2RATCHET_NHKS 0x0000060EUL
#define CKA_X2RATCHET_NR 0x0000060FUL
#define CKA_X2RATCHET_NS 0x00000610UL
#define CKA_X2RATCHET_PNS 0x00000611UL
#define CKA_X2RATCHET_RK 0x00000612UL
#define CKA_HSS_LEVELS 0x00000617UL
#define CKA_HSS_LMS_TYPE 0x00000618UL
#define CKA_HSS_LMOTS_TYPE 0x00000619UL
#define CKA_HSS_LMS_TYPES 0x0000061AUL
#define CKA_HSS_LMOTS_TYPES 0x0000061BUL
#define CKA_HSS_KEYS_REMAINING 0x0000061CUL
#define CKA_PARAMETER_SET 0x0000061DUL
#define CKA_OBJECT_VALIDATION_FLAGS 0x0000061EUL
#define CKA_VALIDATION_TYPE 0x0000061FUL
#define CKA_VALIDATION_VERSION 0x00000620UL
#define CKA_VALIDATION_LEVEL 0x00000621UL
#define CKA_VALIDATION_MODULE_ID 0x00000622UL
#define CKA_VALIDATION_FLAG 0x00000623UL
#define CKA_VALIDATION_AUTHORITY_TYPE 0x00000624UL
#define CKA_VALIDATION_COUNTRY 0x00000625UL
#define CKA_VALIDATION_CERTIFICATE_IDENTIFIER 0x00000626UL
#define CKA_VALIDATION_CERTIFICATE_URI 0x00000627UL
#define CKA_VALIDATION_VENDOR_URI 0x00000628UL
#define CKA_VALIDATION_PROFILE 0x00000629UL
#define CKA_ENCAPSULATE_TEMPLATE 0x0000062AUL
#define CKA_DECAPSULATE_TEMPLATE 0x0000062BUL
#define CKA_TRUST_SERVER_AUTH 0x0000062CUL
#define CKA_TRUST_CLIENT_AUTH 0x0000062DUL
#define CKA_TRUST_CODE_SIGNING 0x0000062EUL
#define CKA_TRUST_EMAIL_PROTECTION 0x0000062FUL
#define CKA_TRUST_IPSEC_IKE 0x00000630UL
#define CKA_TRUST_TIME_STAMPING 0x00000631UL
#define CKA_TRUST_OCSP_SIGNING 0x00000632UL
#define CKA_ENCAPSULATE 0x00000633UL
#define CKA_DECAPSULATE 0x00000634UL
#define CKA_HASH_OF_CERTIFICATE 0x00000635UL
#define CKA_PUBLIC_CRC64_VALUE 0x00000636UL
#define CKA_SEED 0x00000637UL
#define CKA_VENDOR_DEFINED 0x80000000UL
/* Array attributes */
#define CKA_WRAP_TEMPLATE 0x40000211UL
#define CKA_UNWRAP_TEMPLATE 0x40000212UL
#define CKA_DERIVE_TEMPLATE 0x40000213UL
#define CKA_ALLOWED_MECHANISMS 0x40000600UL
/* Deprecated */
#ifdef PKCS11_DEPRECATED
#define CKA_ECDSA_PARAMS 0x00000180UL
#define CKA_SECONDARY_AUTH 0x00000200UL
#define CKA_AUTH_PIN_FLAGS 0x00000201UL
#endif

/* CKC */
#define CKC_X_509 0x00000000UL
#define CKC_X_509_ATTR_CERT 0x00000001UL
#define CKC_WTLS 0x00000002UL
#define CKC_VENDOR_DEFINED 0x80000000UL

/* CKD */
#define CKD_NULL 0x00000001UL
#define CKD_SHA1_KDF 0x00000002UL
#define CKD_SHA1_KDF_ASN1 0x00000003UL
#define CKD_SHA1_KDF_CONCATENATE 0x00000004UL
#define CKD_SHA224_KDF 0x00000005UL
#define CKD_SHA256_KDF 0x00000006UL
#define CKD_SHA384_KDF 0x00000007UL
#define CKD_SHA512_KDF 0x00000008UL
#define CKD_CPDIVERSIFY_KDF 0x00000009UL
#define CKD_SHA3_224_KDF 0x0000000AUL
#define CKD_SHA3_256_KDF 0x0000000BUL
#define CKD_SHA3_384_KDF 0x0000000CUL
#define CKD_SHA3_512_KDF 0x0000000DUL
#define CKD_SHA1_KDF_SP800 0x0000000EUL
#define CKD_SHA224_KDF_SP800 0x0000000FUL
#define CKD_SHA256_KDF_SP800 0x00000010UL
#define CKD_SHA384_KDF_SP800 0x00000011UL
#define CKD_SHA512_KDF_SP800 0x00000012UL
#define CKD_SHA3_224_KDF_SP800 0x00000013UL
#define CKD_SHA3_256_KDF_SP800 0x00000014UL
#define CKD_SHA3_384_KDF_SP800 0x00000015UL
#define CKD_SHA3_512_KDF_SP800 0x00000016UL
#define CKD_BLAKE2B_160_KDF 0x00000017UL
#define CKD_BLAKE2B_256_KDF 0x00000018UL
#define CKD_BLAKE2B_384_KDF 0x00000019UL
#define CKD_BLAKE2B_512_KDF 0x0000001AUL

/* CFK (array attributes) */
#define CKF_ARRAY_ATTRIBUTE 0x40000000UL

/* CKF (capabilities) */
#define CKF_LIBRARY_CANT_CREATE_OS_THREADS 0x00000001UL
#define CKF_OS_LOCKING_OK 0x00000002UL

/* CKF (HKDF) */
#define CKF_HKDF_SALT_NULL 0x00000001UL
#define CKF_HKDF_SALT_DATA 0x00000002UL
#define CKF_HKDF_SALT_KEY 0x00000004UL

/* CKF (interface) */
#define CKF_INTERFACE_FORK_SAFE 0x00000001UL

/* CKF (mechanism) */
#define CKF_HW 0x00000001UL
#define CKF_MESSAGE_ENCRYPT 0x00000002UL
#define CKF_MESSAGE_DECRYPT 0x00000004UL
#define CKF_MESSAGE_SIGN 0x00000008UL
#define CKF_MESSAGE_VERIFY 0x00000010UL
#define CKF_MULTI_MESSAGE 0x00000020UL
#define CKF_MULTI_MESSGE 0x00000020UL
#define CKF_FIND_OBJECTS 0x00000040UL
#define CKF_ENCRYPT 0x00000100UL
#define CKF_DECRYPT 0x00000200UL
#define CKF_DIGEST 0x00000400UL
#define CKF_SIGN 0x00000800UL
#define CKF_SIGN_RECOVER 0x00001000UL
#define CKF_VERIFY 0x00002000UL
#define CKF_VERIFY_RECOVER 0x00004000UL
#define CKF_GENERATE 0x00008000UL
#define CKF_GENERATE_KEY_PAIR 0x00010000UL
#define CKF_WRAP 0x00020000UL
#define CKF_UNWRAP 0x00040000UL
#define CKF_DERIVE 0x00080000UL
#define CKF_EC_F_P 0x00100000UL
#define CKF_EC_F_2M 0x00200000UL
#define CKF_EC_ECPARAMETERS 0x00400000UL
#define CKF_EC_OID 0x00800000UL
#define CKF_EC_UNCOMPRESS 0x01000000UL
#define CKF_EC_COMPRESS 0x02000000UL
#define CKF_EC_CURVENAME 0x04000000UL
#define CKF_ENCAPSULATE 0x10000000UL
#define CKF_DECAPSULATE 0x20000000UL
#define CKF_EXTENSION 0x80000000UL
/* Deprecated */
#ifdef PKCS11_DEPRECATED
#define CKF_EC_NAMEDCURVE 0x00800000U
#endif

/* CKF (message) */
#define CKF_END_OF_MESSAGE 0x00000001UL

/* CKF (OTP) */
#define CKF_NEXT_OTP 0x00000001UL
#define CKF_EXCLUDE_TIME 0x00000002UL
#define CKF_EXCLUDE_COUNTER 0x00000004UL
#define CKF_EXCLUDE_CHALLENGE 0x00000008UL
#define CKF_EXCLUDE_PIN 0x00000010UL
#define CKF_USER_FRIENDLY_OTP 0x00000020UL

/* CKF (parameters to functions) */
#define CKF_DONT_BLOCK 1

/* CKF (session) */
#define CKF_RW_SESSION 0x00000002UL
#define CKF_SERIAL_SESSION 0x00000004UL
#define CKF_ASYNC_SESSION 0x00000008UL

/* CFK (slot) */
#define CKF_TOKEN_PRESENT 0x00000001UL
#define CKF_REMOVABLE_DEVICE 0x00000002UL
#define CKF_HW_SLOT 0x00000004UL

/* CKF (token) */
#define CKF_RNG 0x00000001UL
#define CKF_WRITE_PROTECTED 0x00000002UL
#define CKF_LOGIN_REQUIRED 0x00000004UL
#define CKF_USER_PIN_INITIALIZED 0x00000008UL
#define CKF_RESTORE_KEY_NOT_NEEDED 0x00000020UL
#define CKF_CLOCK_ON_TOKEN 0x00000040UL
#define CKF_PROTECTED_AUTHENTICATION_PATH 0x00000100UL
#define CKF_DUAL_CRYPTO_OPERATIONS 0x00000200UL
#define CKF_TOKEN_INITIALIZED 0x00000400UL
#define CKF_SECONDARY_AUTHENTICATION 0x00000800UL
#define CKF_USER_PIN_COUNT_LOW 0x00010000UL
#define CKF_USER_PIN_FINAL_TRY 0x00020000UL
#define CKF_USER_PIN_LOCKED 0x00040000UL
#define CKF_USER_PIN_TO_BE_CHANGED 0x00080000UL
#define CKF_SO_PIN_COUNT_LOW 0x00100000UL
#define CKF_SO_PIN_FINAL_TRY 0x00200000UL
#define CKF_SO_PIN_LOCKED 0x00400000UL
#define CKF_SO_PIN_TO_BE_CHANGED 0x00800000UL
#define CKF_ERROR_STATE 0x01000000UL
#define CKF_SEED_RANDOM_REQUIRED 0x02000000UL
#define CKF_ASYNC_SESSION_SUPPORTED 0x04000000UL

/* CKG (GCM) */
#define CKG_NO_GENERATE 0x00000000UL
#define CKG_GENERATE 0x00000001UL
#define CKG_GENERATE_COUNTER 0x00000002UL
#define CKG_GENERATE_RANDOM 0x00000003UL
#define CKG_GENERATE_COUNTER_XOR 0x00000004UL

/* CKG (MFG) */
#define CKG_MGF1_SHA1 0x00000001UL
#define CKG_MGF1_SHA256 0x00000002UL
#define CKG_MGF1_SHA384 0x00000003UL
#define CKG_MGF1_SHA512 0x00000004UL
#define CKG_MGF1_SHA224 0x00000005UL
#define CKG_MGF1_SHA3_224 0x00000006UL
#define CKG_MGF1_SHA3_256 0x00000007UL
#define CKG_MGF1_SHA3_384 0x00000008UL
#define CKG_MGF1_SHA3_512 0x00000009UL

/* CKH (clock) */
#define CKH_MONOTONIC_COUNTER 0x00000001UL
#define CKH_CLOCK 0x00000002UL
#define CKH_USER_INTERFACE 0x00000003UL
#define CKH_VENDOR_DEFINED 0x80000000UL

/* CKH (hedge type) */
#define CKH_HEDGE_PREFERRED 0x00000000UL
#define CKH_HEDGE_REQUIRED 0x00000001UL
#define CKH_DETERMINISTIC_REQUIRED 0x00000002UL

/* CKK */
#define CKK_RSA 0x00000000UL
#define CKK_DSA 0x00000001UL
#define CKK_DH 0x00000002UL
#define CKK_EC 0x00000003UL
#define CKK_X9_42_DH 0x00000004UL
#define CKK_KEA 0x00000005UL
#define CKK_GENERIC_SECRET 0x00000010UL
#define CKK_RC2 0x00000011UL
#define CKK_RC4 0x00000012UL
#define CKK_DES 0x00000013UL
#define CKK_DES2 0x00000014UL
#define CKK_DES3 0x00000015UL
#define CKK_CAST 0x00000016UL
#define CKK_CAST3 0x00000017UL
#define CKK_CAST128 0x00000018UL
#define CKK_RC5 0x00000019UL
#define CKK_IDEA 0x0000001AUL
#define CKK_SKIPJACK 0x0000001BUL
#define CKK_BATON 0x0000001CUL
#define CKK_JUNIPER 0x0000001DUL
#define CKK_CDMF 0x0000001EUL
#define CKK_AES 0x0000001FUL
#define CKK_BLOWFISH 0x00000020UL
#define CKK_TWOFISH 0x00000021UL
#define CKK_SECURID 0x00000022UL
#define CKK_HOTP 0x00000023UL
#define CKK_ACTI 0x00000024UL
#define CKK_CAMELLIA 0x00000025UL
#define CKK_ARIA 0x00000026UL
#define CKK_MD5_HMAC 0x00000027UL
#define CKK_SHA_1_HMAC 0x00000028UL
#define CKK_RIPEMD128_HMAC 0x00000029UL
#define CKK_RIPEMD160_HMAC 0x0000002AUL
#define CKK_SHA256_HMAC 0x0000002BUL
#define CKK_SHA384_HMAC 0x0000002CUL
#define CKK_SHA512_HMAC 0x0000002DUL
#define CKK_SHA224_HMAC 0x0000002EUL
#define CKK_SEED 0x0000002FUL
#define CKK_GOSTR3410 0x00000030UL
#define CKK_GOSTR3411 0x00000031UL
#define CKK_GOST28147 0x00000032UL
#define CKK_CHACHA20 0x00000033UL
#define CKK_POLY1305 0x00000034UL
#define CKK_AES_XTS 0x00000035UL
#define CKK_SHA3_224_HMAC 0x00000036UL
#define CKK_SHA3_256_HMAC 0x00000037UL
#define CKK_SHA3_384_HMAC 0x00000038UL
#define CKK_SHA3_512_HMAC 0x00000039UL
#define CKK_BLAKE2B_160_HMAC 0x0000003AUL
#define CKK_BLAKE2B_256_HMAC 0x0000003BUL
#define CKK_BLAKE2B_384_HMAC 0x0000003CUL
#define CKK_BLAKE2B_512_HMAC 0x0000003DUL
#define CKK_SALSA20 0x0000003EUL
#define CKK_X2RATCHET 0x0000003FUL
#define CKK_EC_EDWARDS 0x00000040UL
#define CKK_EC_MONTGOMERY 0x00000041UL
#define CKK_HKDF 0x00000042UL
#define CKK_SHA512_224_HMAC 0x00000043UL
#define CKK_SHA512_256_HMAC 0x00000044UL
#define CKK_SHA512_T_HMAC 0x00000045UL
#define CKK_HSS 0x00000046UL
#define CKK_XMSS 0x00000047UL
#define CKK_XMSSMT 0x00000048UL
#define CKK_ML_KEM 0x00000049UL
#define CKK_ML_DSA 0x0000004AUL
#define CKK_SLH_DSA 0x0000004BUL
#define CKK_VENDOR_DEFINED 0x80000000UL
/* Deprecated */
#ifdef PKCS11_DEPRECATED
#define CKK_ECDSA 0x00000003UL
#define CKK_CAST5 0x00000018UL
#endif

/* CKM */
#define CKM_RSA_PKCS_KEY_PAIR_GEN 0x00000000UL
#define CKM_RSA_PKCS 0x00000001UL
#define CKM_RSA_9796 0x00000002UL
#define CKM_RSA_X_509 0x00000003UL
#define CKM_MD2_RSA_PKCS 0x00000004UL
#define CKM_MD5_RSA_PKCS 0x00000005UL
#define CKM_SHA1_RSA_PKCS 0x00000006UL
#define CKM_RIPEMD128_RSA_PKCS 0x00000007UL
#define CKM_RIPEMD160_RSA_PKCS 0x00000008UL
#define CKM_RSA_PKCS_OAEP 0x00000009UL
#define CKM_RSA_X9_31_KEY_PAIR_GEN 0x0000000AUL
#define CKM_RSA_X9_31 0x0000000BUL
#define CKM_SHA1_RSA_X9_31 0x0000000CUL
#define CKM_RSA_PKCS_PSS 0x0000000DUL
#define CKM_SHA1_RSA_PKCS_PSS 0x0000000EUL
#define CKM_ML_KEM_KEY_PAIR_GEN 0x0000000FUL
#define CKM_DSA_KEY_PAIR_GEN 0x00000010UL
#define CKM_DSA 0x00000011UL
#define CKM_DSA_SHA1 0x00000012UL
#define CKM_DSA_SHA224 0x00000013UL
#define CKM_DSA_SHA256 0x00000014UL
#define CKM_DSA_SHA384 0x00000015UL
#define CKM_DSA_SHA512 0x00000016UL
#define CKM_ML_KEM 0x00000017UL
#define CKM_DSA_SHA3_224 0x00000018UL
#define CKM_DSA_SHA3_256 0x00000019UL
#define CKM_DSA_SHA3_384 0x0000001AUL
#define CKM_DSA_SHA3_512 0x0000001BUL
#define CKM_ML_DSA_KEY_PAIR_GEN 0x0000001CUL
#define CKM_ML_DSA 0x0000001DUL
#define CKM_HASH_ML_DSA 0x0000001FUL
#define CKM_DH_PKCS_KEY_PAIR_GEN 0x00000020UL
#define CKM_DH_PKCS_DERIVE 0x00000021UL
#define CKM_HASH_ML_DSA_SHA224 0x00000023UL
#define CKM_HASH_ML_DSA_SHA256 0x00000024UL
#define CKM_HASH_ML_DSA_SHA384 0x00000025UL
#define CKM_HASH_ML_DSA_SHA512 0x00000026UL
#define CKM_HASH_ML_DSA_SHA3_224 0x00000027UL
#define CKM_HASH_ML_DSA_SHA3_256 0x00000028UL
#define CKM_HASH_ML_DSA_SHA3_384 0x00000029UL
#define CKM_HASH_ML_DSA_SHA3_512 0x0000002AUL
#define CKM_HASH_ML_DSA_SHAKE128 0x0000002BUL
#define CKM_HASH_ML_DSA_SHAKE256 0x0000002CUL
#define CKM_SLH_DSA_KEY_PAIR_GEN 0x0000002DUL
#define CKM_SLH_DSA 0x0000002EUL
#define CKM_X9_42_DH_KEY_PAIR_GEN 0x00000030UL
#define CKM_X9_42_DH_DERIVE 0x00000031UL
#define CKM_X9_42_DH_HYBRID_DERIVE 0x00000032UL
#define CKM_X9_42_MQV_DERIVE 0x00000033UL
#define CKM_HASH_SLH_DSA 0x00000034UL
#define CKM_HASH_SLH_DSA_SHA224 0x00000036UL
#define CKM_HASH_SLH_DSA_SHA256 0x00000037UL
#define CKM_HASH_SLH_DSA_SHA384 0x00000038UL
#define CKM_HASH_SLH_DSA_SHA512 0x00000039UL
#define CKM_HASH_SLH_DSA_SHA3_224 0x0000003AUL
#define CKM_HASH_SLH_DSA_SHA3_256 0x0000003BUL
#define CKM_HASH_SLH_DSA_SHA3_384 0x0000003CUL
#define CKM_HASH_SLH_DSA_SHA3_512 0x0000003DUL
#define CKM_HASH_SLH_DSA_SHAKE128 0x0000003EUL
#define CKM_HASH_SLH_DSA_SHAKE256 0x0000003FUL
#define CKM_SHA256_RSA_PKCS 0x00000040UL
#define CKM_SHA384_RSA_PKCS 0x00000041UL
#define CKM_SHA512_RSA_PKCS 0x00000042UL
#define CKM_SHA256_RSA_PKCS_PSS 0x00000043UL
#define CKM_SHA384_RSA_PKCS_PSS 0x00000044UL
#define CKM_SHA512_RSA_PKCS_PSS 0x00000045UL
#define CKM_SHA224_RSA_PKCS 0x00000046UL
#define CKM_SHA224_RSA_PKCS_PSS 0x00000047UL
#define CKM_SHA512_224 0x00000048UL
#define CKM_SHA512_224_HMAC 0x00000049UL
#define CKM_SHA512_224_HMAC_GENERAL 0x0000004AUL
#define CKM_SHA512_224_KEY_DERIVATION 0x0000004BUL
#define CKM_SHA512_256 0x0000004CUL
#define CKM_SHA512_256_HMAC 0x0000004DUL
#define CKM_SHA512_256_HMAC_GENERAL 0x0000004EUL
#define CKM_SHA512_256_KEY_DERIVATION 0x0000004FUL
#define CKM_SHA512_T 0x00000050UL
#define CKM_SHA512_T_HMAC 0x00000051UL
#define CKM_SHA512_T_HMAC_GENERAL 0x00000052UL
#define CKM_SHA512_T_KEY_DERIVATION 0x00000053UL
#define CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE 0x00000056UL
#define CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH 0x00000057UL
#define CKM_SHA3_256_RSA_PKCS 0x00000060UL
#define CKM_SHA3_384_RSA_PKCS 0x00000061UL
#define CKM_SHA3_512_RSA_PKCS 0x00000062UL
#define CKM_SHA3_256_RSA_PKCS_PSS 0x00000063UL
#define CKM_SHA3_384_RSA_PKCS_PSS 0x00000064UL
#define CKM_SHA3_512_RSA_PKCS_PSS 0x00000065UL
#define CKM_SHA3_224_RSA_PKCS 0x00000066UL
#define CKM_SHA3_224_RSA_PKCS_PSS 0x00000067UL
#define CKM_RC2_KEY_GEN 0x00000100UL
#define CKM_RC2_ECB 0x00000101UL
#define CKM_RC2_CBC 0x00000102UL
#define CKM_RC2_MAC 0x00000103UL
#define CKM_RC2_MAC_GENERAL 0x00000104UL
#define CKM_RC2_CBC_PAD 0x00000105UL
#define CKM_RC4_KEY_GEN 0x00000110UL
#define CKM_RC4 0x00000111UL
#define CKM_DES_KEY_GEN 0x00000120UL
#define CKM_DES_ECB 0x00000121UL
#define CKM_DES_CBC 0x00000122UL
#define CKM_DES_MAC 0x00000123UL
#define CKM_DES_MAC_GENERAL 0x00000124UL
#define CKM_DES_CBC_PAD 0x00000125UL
#define CKM_DES2_KEY_GEN 0x00000130UL
#define CKM_DES3_KEY_GEN 0x00000131UL
#define CKM_DES3_ECB 0x00000132UL
#define CKM_DES3_CBC 0x00000133UL
#define CKM_DES3_MAC 0x00000134UL
#define CKM_DES3_MAC_GENERAL 0x00000135UL
#define CKM_DES3_CBC_PAD 0x00000136UL
#define CKM_DES3_CMAC_GENERAL 0x00000137UL
#define CKM_DES3_CMAC 0x00000138UL
#define CKM_CDMF_KEY_GEN 0x00000140UL
#define CKM_CDMF_ECB 0x00000141UL
#define CKM_CDMF_CBC 0x00000142UL
#define CKM_CDMF_MAC 0x00000143UL
#define CKM_CDMF_MAC_GENERAL 0x00000144UL
#define CKM_CDMF_CBC_PAD 0x00000145UL
#define CKM_DES_OFB64 0x00000150UL
#define CKM_DES_OFB8 0x00000151UL
#define CKM_DES_CFB64 0x00000152UL
#define CKM_DES_CFB8 0x00000153UL
#define CKM_MD2 0x00000200UL
#define CKM_MD2_HMAC 0x00000201UL
#define CKM_MD2_HMAC_GENERAL 0x00000202UL
#define CKM_MD5 0x00000210UL
#define CKM_MD5_HMAC 0x00000211UL
#define CKM_MD5_HMAC_GENERAL 0x00000212UL
#define CKM_SHA_1 0x00000220UL
#define CKM_SHA_1_HMAC 0x00000221UL
#define CKM_SHA_1_HMAC_GENERAL 0x00000222UL
#define CKM_RIPEMD128 0x00000230UL
#define CKM_RIPEMD128_HMAC 0x00000231UL
#define CKM_RIPEMD128_HMAC_GENERAL 0x00000232UL
#define CKM_RIPEMD160 0x00000240UL
#define CKM_RIPEMD160_HMAC 0x00000241UL
#define CKM_RIPEMD160_HMAC_GENERAL 0x00000242UL
#define CKM_SHA256 0x00000250UL
#define CKM_SHA256_HMAC 0x00000251UL
#define CKM_SHA256_HMAC_GENERAL 0x00000252UL
#define CKM_SHA224 0x00000255UL
#define CKM_SHA224_HMAC 0x00000256UL
#define CKM_SHA224_HMAC_GENERAL 0x00000257UL
#define CKM_SHA384 0x00000260UL
#define CKM_SHA384_HMAC 0x00000261UL
#define CKM_SHA384_HMAC_GENERAL 0x00000262UL
#define CKM_SHA512 0x00000270UL
#define CKM_SHA512_HMAC 0x00000271UL
#define CKM_SHA512_HMAC_GENERAL 0x00000272UL
#define CKM_SECURID_KEY_GEN 0x00000280UL
#define CKM_SECURID 0x00000282UL
#define CKM_HOTP_KEY_GEN 0x00000290UL
#define CKM_HOTP 0x00000291UL
#define CKM_ACTI 0x000002A0UL
#define CKM_ACTI_KEY_GEN 0x000002A1UL
#define CKM_SHA3_256 0x000002B0UL
#define CKM_SHA3_256_HMAC 0x000002B1UL
#define CKM_SHA3_256_HMAC_GENERAL 0x000002B2UL
#define CKM_SHA3_256_KEY_GEN 0x000002B3UL
#define CKM_SHA3_224 0x000002B5UL
#define CKM_SHA3_224_HMAC 0x000002B6UL
#define CKM_SHA3_224_HMAC_GENERAL 0x000002B7UL
#define CKM_SHA3_224_KEY_GEN 0x000002B8UL
#define CKM_SHA3_384 0x000002C0UL
#define CKM_SHA3_384_HMAC 0x000002C1UL
#define CKM_SHA3_384_HMAC_GENERAL 0x000002C2UL
#define CKM_SHA3_384_KEY_GEN 0x000002C3UL
#define CKM_SHA3_512 0x000002D0UL
#define CKM_SHA3_512_HMAC 0x000002D1UL
#define CKM_SHA3_512_HMAC_GENERAL 0x000002D2UL
#define CKM_SHA3_512_KEY_GEN 0x000002D3UL
#define CKM_CAST_KEY_GEN 0x00000300UL
#define CKM_CAST_ECB 0x00000301UL
#define CKM_CAST_CBC 0x00000302UL
#define CKM_CAST_MAC 0x00000303UL
#define CKM_CAST_MAC_GENERAL 0x00000304UL
#define CKM_CAST_CBC_PAD 0x00000305UL
#define CKM_CAST3_KEY_GEN 0x00000310UL
#define CKM_CAST3_ECB 0x00000311UL
#define CKM_CAST3_CBC 0x00000312UL
#define CKM_CAST3_MAC 0x00000313UL
#define CKM_CAST3_MAC_GENERAL 0x00000314UL
#define CKM_CAST3_CBC_PAD 0x00000315UL
#define CKM_CAST128_KEY_GEN 0x00000320UL
#define CKM_CAST128_ECB 0x00000321UL
#define CKM_CAST128_MAC 0x00000323UL
#define CKM_CAST128_CBC 0x00000322UL
#define CKM_CAST128_MAC_GENERAL 0x00000324UL
#define CKM_CAST128_CBC_PAD 0x00000325UL
#define CKM_RC5_KEY_GEN 0x00000330UL
#define CKM_RC5_ECB 0x00000331UL
#define CKM_RC5_CBC 0x00000332UL
#define CKM_RC5_MAC 0x00000333UL
#define CKM_RC5_MAC_GENERAL 0x00000334UL
#define CKM_RC5_CBC_PAD 0x00000335UL
#define CKM_IDEA_KEY_GEN 0x00000340UL
#define CKM_IDEA_ECB 0x00000341UL
#define CKM_IDEA_CBC 0x00000342UL
#define CKM_IDEA_MAC 0x00000343UL
#define CKM_IDEA_MAC_GENERAL 0x00000344UL
#define CKM_IDEA_CBC_PAD 0x00000345UL
#define CKM_GENERIC_SECRET_KEY_GEN 0x00000350UL
#define CKM_CONCATENATE_BASE_AND_KEY 0x00000360UL
#define CKM_CONCATENATE_BASE_AND_DATA 0x00000362UL
#define CKM_CONCATENATE_DATA_AND_BASE 0x00000363UL
#define CKM_XOR_BASE_AND_DATA 0x00000364UL
#define CKM_EXTRACT_KEY_FROM_KEY 0x00000365UL
#define CKM_SSL3_PRE_MASTER_KEY_GEN 0x00000370UL
#define CKM_SSL3_MASTER_KEY_DERIVE 0x00000371UL
#define CKM_SSL3_KEY_AND_MAC_DERIVE 0x00000372UL
#define CKM_SSL3_MASTER_KEY_DERIVE_DH 0x00000373UL
#define CKM_TLS_PRE_MASTER_KEY_GEN 0x00000374UL
#define CKM_TLS_MASTER_KEY_DERIVE 0x00000375UL
#define CKM_TLS_KEY_AND_MAC_DERIVE 0x00000376UL
#define CKM_TLS_MASTER_KEY_DERIVE_DH 0x00000377UL
#define CKM_TLS_PRF 0x00000378UL
#define CKM_SSL3_MD5_MAC 0x00000380UL
#define CKM_SSL3_SHA1_MAC 0x00000381UL
#define CKM_MD5_KEY_DERIVATION 0x00000390UL
#define CKM_MD2_KEY_DERIVATION 0x00000391UL
#define CKM_SHA1_KEY_DERIVATION 0x00000392UL
#define CKM_SHA256_KEY_DERIVATION 0x00000393UL
#define CKM_SHA384_KEY_DERIVATION 0x00000394UL
#define CKM_SHA512_KEY_DERIVATION 0x00000395UL
#define CKM_SHA224_KEY_DERIVATION 0x00000396UL
#define CKM_SHA3_256_KEY_DERIVATION 0x00000397UL
#define CKM_SHA3_256_KEY_DERIVE 0x00000397UL
#define CKM_SHA3_224_KEY_DERIVATION 0x00000398UL
#define CKM_SHA3_224_KEY_DERIVE 0x00000398UL
#define CKM_SHA3_384_KEY_DERIVATION 0x00000399UL
#define CKM_SHA3_384_KEY_DERIVE 0x00000399UL
#define CKM_SHA3_512_KEY_DERIVATION 0x0000039AUL
#define CKM_SHA3_512_KEY_DERIVE 0x0000039AUL
#define CKM_SHAKE_128_KEY_DERIVATION 0x0000039BUL
#define CKM_SHAKE_128_KEY_DERIVE 0x0000039BUL
#define CKM_SHAKE_256_KEY_DERIVATION 0x0000039CUL
#define CKM_SHAKE_256_KEY_DERIVE 0x0000039CUL
#define CKM_PBE_MD2_DES_CBC 0x000003A0UL
#define CKM_PBE_MD5_DES_CBC 0x000003A1UL
#define CKM_PBE_MD5_CAST_CBC 0x000003A2UL
#define CKM_PBE_MD5_CAST3_CBC 0x000003A3UL
#define CKM_PBE_MD5_CAST128_CBC 0x000003A4UL
#define CKM_PBE_SHA1_CAST128_CBC 0x000003A5UL
#define CKM_PBE_SHA1_RC4_128 0x000003A6UL
#define CKM_PBE_SHA1_RC4_40 0x000003A7UL
#define CKM_PBE_SHA1_DES3_EDE_CBC 0x000003A8UL
#define CKM_PBE_SHA1_DES2_EDE_CBC 0x000003A9UL
#define CKM_PBE_SHA1_RC2_128_CBC 0x000003AAUL
#define CKM_PBE_SHA1_RC2_40_CBC 0x000003ABUL
#define CKM_PKCS5_PBKD2 0x000003B0UL
#define CKM_PBA_SHA1_WITH_SHA1_HMAC 0x000003C0UL
#define CKM_WTLS_PRE_MASTER_KEY_GEN 0x000003D0UL
#define CKM_WTLS_MASTER_KEY_DERIVE 0x000003D1UL
#define CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC 0x000003D2UL
#define CKM_WTLS_PRF 0x000003D3UL
#define CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE 0x000003D4UL
#define CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE 0x000003D5UL
#define CKM_TLS10_MAC_SERVER 0x000003D6UL
#define CKM_TLS10_MAC_CLIENT 0x000003D7UL
#define CKM_TLS12_MAC 0x000003D8UL
#define CKM_TLS12_KDF 0x000003D9UL
#define CKM_TLS12_MASTER_KEY_DERIVE 0x000003E0UL
#define CKM_TLS12_KEY_AND_MAC_DERIVE 0x000003E1UL
#define CKM_TLS12_MASTER_KEY_DERIVE_DH 0x000003E2UL
#define CKM_TLS12_KEY_SAFE_DERIVE 0x000003E3UL
#define CKM_TLS_MAC 0x000003E4UL
#define CKM_TLS_KDF 0x000003E5UL
#define CKM_KEY_WRAP_LYNKS 0x00000400UL
#define CKM_KEY_WRAP_SET_OAEP 0x00000401UL
#define CKM_CMS_SIG 0x00000500UL
#define CKM_KIP_DERIVE 0x00000510UL
#define CKM_KIP_WRAP 0x00000511UL
#define CKM_KIP_MAC 0x00000512UL
#define CKM_CAMELLIA_KEY_GEN 0x00000550UL
#define CKM_CAMELLIA_ECB 0x00000551UL
#define CKM_CAMELLIA_CBC 0x00000552UL
#define CKM_CAMELLIA_MAC 0x00000553UL
#define CKM_CAMELLIA_MAC_GENERAL 0x00000554UL
#define CKM_CAMELLIA_CBC_PAD 0x00000555UL
#define CKM_CAMELLIA_ECB_ENCRYPT_DATA 0x00000556UL
#define CKM_CAMELLIA_CBC_ENCRYPT_DATA 0x00000557UL
#define CKM_CAMELLIA_CTR 0x00000558UL
#define CKM_ARIA_KEY_GEN 0x00000560UL
#define CKM_ARIA_ECB 0x00000561UL
#define CKM_ARIA_CBC 0x00000562UL
#define CKM_ARIA_MAC 0x00000563UL
#define CKM_ARIA_MAC_GENERAL 0x00000564UL
#define CKM_ARIA_CBC_PAD 0x00000565UL
#define CKM_ARIA_ECB_ENCRYPT_DATA 0x00000566UL
#define CKM_ARIA_CBC_ENCRYPT_DATA 0x00000567UL
#define CKM_SEED_KEY_GEN 0x00000650UL
#define CKM_SEED_ECB 0x00000651UL
#define CKM_SEED_CBC 0x00000652UL
#define CKM_SEED_MAC 0x00000653UL
#define CKM_SEED_MAC_GENERAL 0x00000654UL
#define CKM_SEED_CBC_PAD 0x00000655UL
#define CKM_SEED_ECB_ENCRYPT_DATA 0x00000656UL
#define CKM_SEED_CBC_ENCRYPT_DATA 0x00000657UL
#define CKM_SKIPJACK_KEY_GEN 0x00001000UL
#define CKM_SKIPJACK_ECB64 0x00001001UL
#define CKM_SKIPJACK_CBC64 0x00001002UL
#define CKM_SKIPJACK_OFB64 0x00001003UL
#define CKM_SKIPJACK_CFB64 0x00001004UL
#define CKM_SKIPJACK_CFB32 0x00001005UL
#define CKM_SKIPJACK_CFB16 0x00001006UL
#define CKM_SKIPJACK_CFB8 0x00001007UL
#define CKM_SKIPJACK_WRAP 0x00001008UL
#define CKM_SKIPJACK_PRIVATE_WRAP 0x00001009UL
#define CKM_SKIPJACK_RELAYX 0x0000100AUL
#define CKM_KEA_KEY_PAIR_GEN 0x00001010UL
#define CKM_KEA_KEY_DERIVE 0x00001011UL
#define CKM_KEA_DERIVE 0x00001012UL
#define CKM_FORTEZZA_TIMESTAMP 0x00001020UL
#define CKM_BATON_KEY_GEN 0x00001030UL
#define CKM_BATON_ECB128 0x00001031UL
#define CKM_BATON_ECB96 0x00001032UL
#define CKM_BATON_CBC128 0x00001033UL
#define CKM_BATON_COUNTER 0x00001034UL
#define CKM_BATON_SHUFFLE 0x00001035UL
#define CKM_BATON_WRAP 0x00001036UL
#define CKM_EC_KEY_PAIR_GEN 0x00001040UL
#define CKM_ECDSA 0x00001041UL
#define CKM_ECDSA_SHA1 0x00001042UL
#define CKM_ECDSA_SHA224 0x00001043UL
#define CKM_ECDSA_SHA256 0x00001044UL
#define CKM_ECDSA_SHA384 0x00001045UL
#define CKM_ECDSA_SHA512 0x00001046UL
#define CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS 0x0000140BUL
#define CKM_ECDH1_DERIVE 0x00001050UL
#define CKM_ECDH1_COFACTOR_DERIVE 0x00001051UL
#define CKM_ECMQV_DERIVE 0x00001052UL
#define CKM_ECDH_AES_KEY_WRAP 0x00001053UL
#define CKM_RSA_AES_KEY_WRAP 0x00001054UL
#define CKM_JUNIPER_KEY_GEN 0x00001060UL
#define CKM_JUNIPER_ECB128 0x00001061UL
#define CKM_JUNIPER_CBC128 0x00001062UL
#define CKM_JUNIPER_COUNTER 0x00001063UL
#define CKM_JUNIPER_SHUFFLE 0x00001064UL
#define CKM_JUNIPER_WRAP 0x00001065UL
#define CKM_FASTHASH 0x00001070UL
#define CKM_AES_XTS 0x00001071UL
#define CKM_AES_XTS_KEY_GEN 0x00001072UL
#define CKM_AES_KEY_GEN 0x00001080UL
#define CKM_AES_ECB 0x00001081UL
#define CKM_AES_CBC 0x00001082UL
#define CKM_AES_MAC 0x00001083UL
#define CKM_AES_MAC_GENERAL 0x00001084UL
#define CKM_AES_CBC_PAD 0x00001085UL
#define CKM_AES_CTR 0x00001086UL
#define CKM_AES_GCM 0x00001087UL
#define CKM_AES_CCM 0x00001088UL
#define CKM_AES_CTS 0x00001089UL
#define CKM_AES_CMAC 0x0000108AUL
#define CKM_AES_CMAC_GENERAL 0x0000108BUL
#define CKM_AES_XCBC_MAC 0x0000108CUL
#define CKM_AES_XCBC_MAC_96 0x0000108DUL
#define CKM_AES_GMAC 0x0000108EUL
#define CKM_BLOWFISH_KEY_GEN 0x00001090UL
#define CKM_BLOWFISH_CBC 0x00001091UL
#define CKM_TWOFISH_KEY_GEN 0x00001092UL
#define CKM_TWOFISH_CBC 0x00001093UL
#define CKM_BLOWFISH_CBC_PAD 0x00001094UL
#define CKM_TWOFISH_CBC_PAD 0x00001095UL
#define CKM_DES_ECB_ENCRYPT_DATA 0x00001100UL
#define CKM_DES_CBC_ENCRYPT_DATA 0x00001101UL
#define CKM_DES3_ECB_ENCRYPT_DATA 0x00001102UL
#define CKM_DES3_CBC_ENCRYPT_DATA 0x00001103UL
#define CKM_AES_ECB_ENCRYPT_DATA 0x00001104UL
#define CKM_AES_CBC_ENCRYPT_DATA 0x00001105UL
#define CKM_GOSTR3410_KEY_PAIR_GEN 0x00001200UL
#define CKM_GOSTR3410 0x00001201UL
#define CKM_GOSTR3410_WITH_GOSTR3411 0x00001202UL
#define CKM_GOSTR3410_KEY_WRAP 0x00001203UL
#define CKM_GOSTR3410_DERIVE 0x00001204UL
#define CKM_GOSTR3411 0x00001210UL
#define CKM_GOSTR3411_HMAC 0x00001211UL
#define CKM_GOST28147_KEY_GEN 0x00001220UL
#define CKM_GOST28147_ECB 0x00001221UL
#define CKM_GOST28147 0x00001222UL
#define CKM_GOST28147_MAC 0x00001223UL
#define CKM_GOST28147_KEY_WRAP 0x00001224UL
#define CKM_CHACHA20_KEY_GEN 0x00001225UL
#define CKM_CHACHA20 0x00001226UL
#define CKM_POLY1305_KEY_GEN 0x00001227UL
#define CKM_POLY1305 0x00001228UL
#define CKM_DSA_PARAMETER_GEN 0x00002000UL
#define CKM_DH_PKCS_PARAMETER_GEN 0x00002001UL
#define CKM_X9_42_DH_PARAMETER_GEN 0x00002002UL
#define CKM_DSA_PROBABILISTIC_PARAMETER_GEN 0x00002003UL
#define CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN 0x00002004UL
#define CKM_DSA_FIPS_G_GEN 0x00002005UL
#define CKM_AES_OFB 0x00002104UL
#define CKM_AES_CFB64 0x00002105UL
#define CKM_AES_CFB8 0x00002106UL
#define CKM_AES_CFB128 0x00002107UL
#define CKM_AES_CFB1 0x00002108UL
#define CKM_AES_KEY_WRAP 0x00002109UL
#define CKM_AES_KEY_WRAP_PAD 0x0000210AUL
#define CKM_AES_KEY_WRAP_KWP 0x0000210BUL
#define CKM_AES_KEY_WRAP_PKCS7 0x0000210CUL
#define CKM_RSA_PKCS_TPM_1_1 0x00004001UL
#define CKM_RSA_PKCS_OAEP_TPM_1_1 0x00004002UL
#define CKM_SHA_1_KEY_GEN 0x00004003UL
#define CKM_SHA224_KEY_GEN 0x00004004UL
#define CKM_SHA256_KEY_GEN 0x00004005UL
#define CKM_SHA384_KEY_GEN 0x00004006UL
#define CKM_SHA512_KEY_GEN 0x00004007UL
#define CKM_SHA512_224_KEY_GEN 0x00004008UL
#define CKM_SHA512_256_KEY_GEN 0x00004009UL
#define CKM_SHA512_T_KEY_GEN 0x0000400AUL
#define CKM_NULL 0x0000400BUL
#define CKM_BLAKE2B_160 0x0000400CUL
#define CKM_BLAKE2B_160_HMAC 0x0000400DUL
#define CKM_BLAKE2B_160_HMAC_GENERAL 0x0000400EUL
#define CKM_BLAKE2B_160_KEY_DERIVE 0x0000400FUL
#define CKM_BLAKE2B_160_KEY_GEN 0x00004010UL
#define CKM_BLAKE2B_256 0x00004011UL
#define CKM_BLAKE2B_256_HMAC 0x00004012UL
#define CKM_BLAKE2B_256_HMAC_GENERAL 0x00004013UL
#define CKM_BLAKE2B_256_KEY_DERIVE 0x00004014UL
#define CKM_BLAKE2B_256_KEY_GEN 0x00004015UL
#define CKM_BLAKE2B_384 0x00004016UL
#define CKM_BLAKE2B_384_HMAC 0x00004017UL
#define CKM_BLAKE2B_384_HMAC_GENERAL 0x00004018UL
#define CKM_BLAKE2B_384_KEY_DERIVE 0x00004019UL
#define CKM_BLAKE2B_384_KEY_GEN 0x0000401AUL
#define CKM_BLAKE2B_512 0x0000401BUL
#define CKM_BLAKE2B_512_HMAC 0x0000401CUL
#define CKM_BLAKE2B_512_HMAC_GENERAL 0x0000401DUL
#define CKM_BLAKE2B_512_KEY_DERIVE 0x0000401EUL
#define CKM_BLAKE2B_512_KEY_GEN 0x0000401FUL
#define CKM_SALSA20 0x00004020UL
#define CKM_CHACHA20_POLY1305 0x00004021UL
#define CKM_SALSA20_POLY1305 0x00004022UL
#define CKM_X3DH_INITIALIZE 0x00004023UL
#define CKM_X3DH_RESPOND 0x00004024UL
#define CKM_X2RATCHET_INITIALIZE 0x00004025UL
#define CKM_X2RATCHET_RESPOND 0x00004026UL
#define CKM_X2RATCHET_ENCRYPT 0x00004027UL
#define CKM_X2RATCHET_DECRYPT 0x00004028UL
#define CKM_XEDDSA 0x00004029UL
#define CKM_HKDF_DERIVE 0x0000402AUL
#define CKM_HKDF_DATA 0x0000402BUL
#define CKM_HKDF_KEY_GEN 0x0000402CUL
#define CKM_SALSA20_KEY_GEN 0x0000402DUL
#define CKM_ECDSA_SHA3_224 0x00001047UL
#define CKM_ECDSA_SHA3_256 0x00001048UL
#define CKM_ECDSA_SHA3_384 0x00001049UL
#define CKM_ECDSA_SHA3_512 0x0000104AUL
#define CKM_EC_EDWARDS_KEY_PAIR_GEN 0x00001055UL
#define CKM_EC_MONTGOMERY_KEY_PAIR_GEN 0x00001056UL
#define CKM_EDDSA 0x00001057UL
#define CKM_SP800_108_COUNTER_KDF 0x000003ACUL
#define CKM_SP800_108_FEEDBACK_KDF 0x000003ADUL
#define CKM_SP800_108_DOUBLE_PIPELINE_KDF 0x000003AEUL
#define CKM_IKE2_PRF_PLUS_DERIVE 0x0000402EUL
#define CKM_IKE_PRF_DERIVE 0x0000402FUL
#define CKM_IKE1_PRF_DERIVE 0x00004030UL
#define CKM_IKE1_EXTENDED_DERIVE 0x00004031UL
#define CKM_HSS_KEY_PAIR_GEN 0x00004032UL
#define CKM_HSS 0x00004033UL
#define CKM_XMSS_KEY_PAIR_GEN 0x00004034UL
#define CKM_XMSSMT_KEY_PAIR_GEN 0x00004035UL
#define CKM_XMSS 0x00004036UL
#define CKM_XMSSMT 0x00004037UL
#define CKM_ECDH_X_AES_KEY_WRAP 0x00004038UL
#define CKM_ECDH_COF_AES_KEY_WRAP 0x00004039UL
#define CKM_PUB_KEY_FROM_PRIV_KEY 0x0000403AUL
#define CKM_VENDOR_DEFINED 0x80000000UL
/* Deprecated */
#ifdef PKCS11_DEPRECATED
#define CKM_CAST5_KEY_GEN 0x00000320UL
#define CKM_CAST5_ECB 0x00000321UL
#define CKM_CAST5_CBC 0x00000322UL
#define CKM_CAST5_MAC 0x00000323UL
#define CKM_CAST5_MAC_GENERAL 0x00000324UL
#define CKM_CAST5_CBC_PAD 0x00000325UL
#define CKM_PBE_MD5_CAST5_CBC 0x000003A4UL
#define CKM_PBE_SHA1_CAST5_CBC 0x000003A5UL
#define CKM_ECDSA_KEY_PAIR_GEN 0x00001040UL
#define CKM_DSA_PROBABLISTIC_PARAMETER_GEN 0x00002003UL
#endif

/* CKN */
#define CKN_SURRENDER 0UL
#define CKN_OTP_CHANGED 1UL

/* CKO */
#define CKO_DATA 0x00000000UL
#define CKO_CERTIFICATE 0x00000001UL
#define CKO_PUBLIC_KEY 0x00000002UL
#define CKO_PRIVATE_KEY 0x00000003UL
#define CKO_SECRET_KEY 0x00000004UL
#define CKO_HW_FEATURE 0x00000005UL
#define CKO_DOMAIN_PARAMETERS 0x00000006UL
#define CKO_MECHANISM 0x00000007UL
#define CKO_OTP_KEY 0x00000008UL
#define CKO_PROFILE 0x00000009UL
#define CKO_VALIDATION 0x0000000AUL
#define CKO_TRUST 0x0000000BUL
#define CKO_VENDOR_DEFINED 0x80000000UL

/* CKP (profile) */
#define CKP_INVALID_ID 0x00000000UL
#define CKP_BASELINE_PROVIDER 0x00000001UL
#define CKP_EXTENDED_PROVIDER 0x00000002UL
#define CKP_AUTHENTICATION_TOKEN 0x00000003UL
#define CKP_PUBLIC_CERTIFICATES_TOKEN 0x00000004UL
#define CKP_COMPLETE_PROVIDER 0x00000005UL
#define CKP_HKDF_TLS_TOKEN 0x00000006UL
#define CKP_VENDOR_DEFINED 0x80000000UL

/* CKP (PBKD2) */
#define CKP_PKCS5_PBKD2_HMAC_SHA1 0x00000001UL
#define CKP_PKCS5_PBKD2_HMAC_GOSTR3411 0x00000002UL
#define CKP_PKCS5_PBKD2_HMAC_SHA224 0x00000003UL
#define CKP_PKCS5_PBKD2_HMAC_SHA256 0x00000004UL
#define CKP_PKCS5_PBKD2_HMAC_SHA384 0x00000005UL
#define CKP_PKCS5_PBKD2_HMAC_SHA512 0x00000006UL
#define CKP_PKCS5_PBKD2_HMAC_SHA512_224 0x00000007UL
#define CKP_PKCS5_PBKD2_HMAC_SHA512_256 0x00000008UL

/* CKP (ML-DSA) */
#define CKP_ML_DSA_44 0x00000001UL
#define CKP_ML_DSA_65 0x00000002UL
#define CKP_ML_DSA_87 0x00000003UL

/* CKP (ML_KEM) */
#define CKP_ML_KEM_512 0x00000001UL
#define CKP_ML_KEM_768 0x00000002UL
#define CKP_ML_KEM_1024 0x00000003UL

/* CKP (SLH-DSA) */
#define CKP_SLH_DSA_SHA2_128S 0x00000001UL
#define CKP_SLH_DSA_SHAKE_128S 0x00000002UL
#define CKP_SLH_DSA_SHA2_128F 0x00000003UL
#define CKP_SLH_DSA_SHAKE_128F 0x00000004UL
#define CKP_SLH_DSA_SHA2_192S 0x00000005UL
#define CKP_SLH_DSA_SHAKE_192S 0x00000006UL
#define CKP_SLH_DSA_SHA2_192F 0x00000007UL
#define CKP_SLH_DSA_SHAKE_192F 0x00000008UL
#define CKP_SLH_DSA_SHA2_256S 0x00000009UL
#define CKP_SLH_DSA_SHAKE_256S 0x0000000AUL
#define CKP_SLH_DSA_SHA2_256F 0x0000000BUL
#define CKP_SLH_DSA_SHAKE_256F 0x0000000CUL

/* CKR */
#define CKR_OK 0x00000000UL
#define CKR_CANCEL 0x00000001UL
#define CKR_HOST_MEMORY 0x00000002UL
#define CKR_SLOT_ID_INVALID 0x00000003UL
#define CKR_GENERAL_ERROR 0x00000005UL
#define CKR_FUNCTION_FAILED 0x00000006UL
#define CKR_ARGUMENTS_BAD 0x00000007UL
#define CKR_NO_EVENT 0x00000008UL
#define CKR_NEED_TO_CREATE_THREADS 0x00000009UL
#define CKR_CANT_LOCK 0x0000000AUL
#define CKR_ATTRIBUTE_READ_ONLY 0x00000010UL
#define CKR_ATTRIBUTE_SENSITIVE 0x00000011UL
#define CKR_ATTRIBUTE_TYPE_INVALID 0x00000012UL
#define CKR_ATTRIBUTE_VALUE_INVALID 0x00000013UL
#define CKR_ACTION_PROHIBITED 0x0000001BUL
#define CKR_DATA_INVALID 0x00000020UL
#define CKR_DATA_LEN_RANGE 0x00000021UL
#define CKR_DEVICE_ERROR 0x00000030UL
#define CKR_DEVICE_MEMORY 0x00000031UL
#define CKR_DEVICE_REMOVED 0x00000032UL
#define CKR_ENCRYPTED_DATA_INVALID 0x00000040UL
#define CKR_ENCRYPTED_DATA_LEN_RANGE 0x00000041UL
#define CKR_AEAD_DECRYPT_FAILED 0x00000042UL
#define CKR_FUNCTION_CANCELED 0x00000050UL
#define CKR_FUNCTION_NOT_PARALLEL 0x00000051UL
#define CKR_FUNCTION_NOT_SUPPORTED 0x00000054UL
#define CKR_KEY_HANDLE_INVALID 0x00000060UL
#define CKR_KEY_SIZE_RANGE 0x00000062UL
#define CKR_KEY_TYPE_INCONSISTENT 0x00000063UL
#define CKR_KEY_NOT_NEEDED 0x00000064UL
#define CKR_KEY_CHANGED 0x00000065UL
#define CKR_KEY_NEEDED 0x00000066UL
#define CKR_KEY_INDIGESTIBLE 0x00000067UL
#define CKR_KEY_FUNCTION_NOT_PERMITTED 0x00000068UL
#define CKR_KEY_NOT_WRAPPABLE 0x00000069UL
#define CKR_KEY_UNEXTRACTABLE 0x0000006AUL
#define CKR_MECHANISM_INVALID 0x00000070UL
#define CKR_MECHANISM_PARAM_INVALID 0x00000071UL
#define CKR_OBJECT_HANDLE_INVALID 0x00000082UL
#define CKR_OPERATION_ACTIVE 0x00000090UL
#define CKR_OPERATION_NOT_INITIALIZED 0x00000091UL
#define CKR_PIN_INCORRECT 0x000000A0UL
#define CKR_PIN_INVALID 0x000000A1UL
#define CKR_PIN_LEN_RANGE 0x000000A2UL
#define CKR_PIN_EXPIRED 0x000000A3UL
#define CKR_PIN_LOCKED 0x000000A4UL
#define CKR_SESSION_CLOSED 0x000000B0UL
#define CKR_SESSION_COUNT 0x000000B1UL
#define CKR_SESSION_HANDLE_INVALID 0x000000B3UL
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED 0x000000B4UL
#define CKR_SESSION_READ_ONLY 0x000000B5UL
#define CKR_SESSION_EXISTS 0x000000B6UL
#define CKR_SESSION_READ_ONLY_EXISTS 0x000000B7UL
#define CKR_SESSION_READ_WRITE_SO_EXISTS 0x000000B8UL
#define CKR_SIGNATURE_INVALID 0x000000C0UL
#define CKR_SIGNATURE_LEN_RANGE 0x000000C1UL
#define CKR_TEMPLATE_INCOMPLETE 0x000000D0UL
#define CKR_TEMPLATE_INCONSISTENT 0x000000D1UL
#define CKR_TOKEN_NOT_PRESENT 0x000000E0UL
#define CKR_TOKEN_NOT_RECOGNIZED 0x000000E1UL
#define CKR_TOKEN_WRITE_PROTECTED 0x000000E2UL
#define CKR_UNWRAPPING_KEY_HANDLE_INVALID 0x000000F0UL
#define CKR_UNWRAPPING_KEY_SIZE_RANGE 0x000000F1UL
#define CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT 0x000000F2UL
#define CKR_USER_ALREADY_LOGGED_IN 0x00000100UL
#define CKR_USER_NOT_LOGGED_IN 0x00000101UL
#define CKR_USER_PIN_NOT_INITIALIZED 0x00000102UL
#define CKR_USER_TYPE_INVALID 0x00000103UL
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN 0x00000104UL
#define CKR_USER_TOO_MANY_TYPES 0x00000105UL
#define CKR_WRAPPED_KEY_INVALID 0x00000110UL
#define CKR_WRAPPED_KEY_LEN_RANGE 0x00000112UL
#define CKR_WRAPPING_KEY_HANDLE_INVALID 0x00000113UL
#define CKR_WRAPPING_KEY_SIZE_RANGE 0x00000114UL
#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT 0x00000115UL
#define CKR_RANDOM_SEED_NOT_SUPPORTED 0x00000120UL
#define CKR_RANDOM_NO_RNG 0x00000121UL
#define CKR_DOMAIN_PARAMS_INVALID 0x00000130UL
#define CKR_CURVE_NOT_SUPPORTED 0x00000140UL
#define CKR_BUFFER_TOO_SMALL 0x00000150UL
#define CKR_SAVED_STATE_INVALID 0x00000160UL
#define CKR_INFORMATION_SENSITIVE 0x00000170UL
#define CKR_STATE_UNSAVEABLE 0x00000180UL
#define CKR_CRYPTOKI_NOT_INITIALIZED 0x00000190UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191UL
#define CKR_MUTEX_BAD 0x000001A0UL
#define CKR_MUTEX_NOT_LOCKED 0x000001A1UL
#define CKR_NEW_PIN_MODE 0x000001B0UL
#define CKR_NEXT_OTP 0x000001B1UL
#define CKR_EXCEEDED_MAX_ITERATIONS 0x000001B5UL
#define CKR_FIPS_SELF_TEST_FAILED 0x000001B6UL
#define CKR_LIBRARY_LOAD_FAILED 0x000001B7UL
#define CKR_PIN_TOO_WEAK 0x000001B8UL
#define CKR_PUBLIC_KEY_INVALID 0x000001B9UL
#define CKR_FUNCTION_REJECTED 0x00000200UL
#define CKR_TOKEN_RESOURCE_EXCEEDED 0x00000201UL
#define CKR_OPERATION_CANCEL_FAILED 0x00000202UL
#define CKR_KEY_EXHAUSTED 0x00000203UL
#define CKR_PENDING 0x00000204UL
#define CKR_SESSION_ASYNC_NOT_SUPPORTED 0x00000205UL
#define CKR_SEED_RANDOM_REQUIRED 0x00000206UL
#define CKR_OPERATION_NOT_VALIDATED 0x00000207UL
#define CKR_TOKEN_NOT_INITIALIZED 0x00000208UL
#define CKR_PARAMETER_SET_NOT_SUPPORTED 0x00000209UL
#define CKR_VENDOR_DEFINED 0x80000000UL

/* CKS */
#define CKS_RO_PUBLIC_SESSION 0UL
#define CKS_RO_USER_FUNCTIONS 1UL
#define CKS_RW_PUBLIC_SESSION 2UL
#define CKS_RW_USER_FUNCTIONS 3UL
#define CKS_RW_SO_FUNCTIONS 4UL

/* CKS (validation) */
#define CKS_LAST_VALIDATION_OK 0x00000001UL

/* CKT (trust) */
#define CKT_TRUST_UNKNOWN 0x00000000UL
#define CKT_TRUSTED 0x00000001UL
#define CKT_TRUST_ANCHOR 0x00000002UL
#define CKT_NOT_TRUSTED 0x00000003UL
#define CKT_TRUST_MUST_VERIFY_TRUST 0x00000004UL

/* CKU */
#define CKU_SO 0UL
#define CKU_USER 1UL
#define CKU_CONTEXT_SPECIFIC 2UL

/* CKV (validation authority) */
#define CKV_AUTHORITY_TYPE_UNSPECIFIED 0x00000000UL
#define CKV_AUTHORITY_TYPE_NIST_CMVP 0x00000001UL
#define CKV_AUTHORITY_TYPE_COMMON_CRITERIA 0x00000002UL

/* CKV (validation type) */
#define CKV_TYPE_UNSPECIFIED 0x00000000UL
#define CKV_TYPE_SOFTWARE 0x00000001UL
#define CKV_TYPE_HARDWARE 0x00000002UL
#define CKV_TYPE_FIRMWARE 0x00000003UL
#define CKV_TYPE_HYBRID 0x00000004UL

/* CKZ (data) */
#define CKZ_DATA_SPECIFIED 0x00000001UL

/* CKZ (salt) */
#define CKZ_SALT_SPECIFIED 0x00000001UL


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
	bool IsAttributeList() const;
	bool IsBin() const;

	PyKCS11String GetString() const;
	void SetString(unsigned long attrType, const char* szValue);

	long GetNum() const;
	void SetNum(unsigned long attrType, unsigned long ulValue);

	bool GetBool() const;
	void SetBool(unsigned long attrType, bool bValue);
	void SetList(unsigned long attrType, const vector<CK_ATTRIBUTE_SMART>& val);

	vector<unsigned char> GetBin();
	void SetBin(unsigned long attrType, const vector<unsigned char>& pBuf);
};
