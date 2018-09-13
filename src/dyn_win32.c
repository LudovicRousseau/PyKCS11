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

#if defined(WIN32) || defined(_WIN32)
#include <string.h>

#include "windows.h"
#include <strsafe.h>
#include <winscard.h>
#include "dyn_generic.h"

/* copy from https://docs.microsoft.com/fr-fr/windows/desktop/Debug/retrieving-the-last-error-code */
static void DisplayError(LPTSTR lpszFunction)
{
    // Retrieve the system error message for the last-error code

    LPTSTR lpMsgBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    // Display the error message
    printf("%s failed with error %d: %s\n", lpszFunction, dw, lpMsgBuf);

    LocalFree(lpMsgBuf);
}


int SYS_dyn_LoadLibrary(void **pvLHandle, const char *pcLibrary)
{
	*pvLHandle = NULL;
	*pvLHandle = LoadLibrary(pcLibrary);

	if (*pvLHandle == NULL)
	{
		DisplayError("LoadLibrary()");
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
		DisplayError("FreeLibrary()");
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
		DisplayError("GetProcAddress()");
		rv = -1;
	}
	else
		rv = 0;

	return rv;
}

#endif	/* WIN32 */

