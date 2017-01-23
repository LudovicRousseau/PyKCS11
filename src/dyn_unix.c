/*
 * This abstracts dynamic library loading functions and timing.
 *
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999
 *  David Corcoran <corcoran@linuxnet.com>
 * Copyright (C) 2004-2009
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id: dyn_unix.c,v 1.13 2005/02/22 14:40:26 rousseau Exp $
 */

//#include "config.h"
#define HAVE_DLFCN_H
#include <stdio.h>
#include <string.h>
#if defined(HAVE_DLFCN_H) && !defined(HAVE_DL_H)
#include <dlfcn.h>
#include <stdlib.h>

#include "dyn_generic.h"

#define Log2(a, b) printf("%s:%d:%s() " a "\n", __FILE__, __LINE__, __FUNCTION__, b);
#define Log3(a, b, c) printf("%s:%d:%s() " a "\n", __FILE__, __LINE__, __FUNCTION__, b, c);

int SYS_dyn_LoadLibrary(void **handle, const char *library_name)
{
	*handle = NULL;
	*handle = dlopen(library_name, RTLD_NOW);

	if (*handle == NULL)
	{
		Log2("%s", dlerror());
		return -1;
	}

	return 0;
} /* SYS_dyn_LoadLibrary */

int SYS_dyn_CloseLibrary(void **handle)
{
	int ret;

	ret = dlclose(*handle);
	*handle = NULL;

	if (ret)
	{
		Log2("%s", dlerror());
		return -1;
	}

	return 0;
} /* SYS_dyn_CloseLibrary */

int SYS_dyn_GetAddress(void *handle, function_ptr *func_ptr,
	const char *function_name)
{
	char new_function_name[256];
	int rv;

	/* Some platforms might need a leading underscore for the symbol */
	snprintf(new_function_name, sizeof(new_function_name), "_%s",
		function_name);

	*func_ptr = NULL;
	*func_ptr = dlsym(handle, new_function_name);

	/* Failed? Try again without the leading underscore */
	if (*func_ptr == NULL)
		*func_ptr = dlsym(handle, function_name);

	if (*func_ptr == NULL)
	{
		Log3("%s: %s", function_name, dlerror());
		rv = -1;
	} else
		rv = 0;

	return rv;
} /* SYS_dyn_GetAddress */

#endif	/* HAVE_DLFCN_H && !HAVE_DL_H && !__APPLE__ */

