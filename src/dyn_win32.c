/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999
 *  David Corcoran <corcoran@linuxnet.com>
 *
 * $Id: dyn_win32.c 1957 2006-03-21 13:59:18Z rousseau $
 */

/**
 * @file
 * @brief This abstracts dynamic library loading functions and timing.
 */

//#include "config.h"
#if defined(WIN32) || defined(_WIN32)
#include <string.h>

#include "windows.h"
#include <winscard.h>
#include "dyn_generic.h"
//#include "debug.h"

int SYS_dyn_LoadLibrary(void **pvLHandle, const char *pcLibrary)
{
	*pvLHandle = NULL;
	*pvLHandle = LoadLibrary(pcLibrary);

	if (*pvLHandle == NULL)
	{
#if 0
		Log2(PCSC_LOG_ERROR, "DYN_LoadLibrary: dlerror() reports %s", dlerror());
#endif
		return -1;
	}

	return 0;
}

int SYS_dyn_CloseLibrary(void **pvLHandle)
{
	int ret;

	ret = FreeLibrary(*pvLHandle);
	*pvLHandle = NULL;

	/* If the function fails, the return value is zero. To get extended error
	 * information, call GetLastError. */
	if (ret == 0)
	{
#if 0
		Log2(PCSC_LOG_ERROR, "DYN_CloseLibrary: dlerror() reports %s", dlerror());
#endif
		return -1;
	}

	return 0;
}

int SYS_dyn_GetAddress(void *pvLHandle, function_ptr *pvFHandle,
        const char *pcFunction)
{
	int rv;
	const char *pcFunctionName;

	/*
	 * Zero out everything
	 */
	rv = 0;
	pcFunctionName = NULL;

	pcFunctionName = pcFunction;

	*pvFHandle = NULL;
	*pvFHandle = (function_ptr)GetProcAddress(pvLHandle, pcFunctionName);

	if (*pvFHandle == NULL)
	{
#if 0
		Log2(PCSC_LOG_ERROR, "DYN_GetAddress: dlerror() reports %s", dlerror());
#endif
		rv = -1;
	}
	else
		rv = 0;

	return rv;
}

#endif	/* WIN32 */

