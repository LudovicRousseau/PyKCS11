/*
 * This abstracts dynamic library loading functions.
 *
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999
 *  David Corcoran <corcoran@linuxnet.com>
 *
 * $Id: dyn_generic.h,v 1.3 2003/10/18 17:19:36 aet-guest Exp $
 */
 
#ifndef __dyn_generic_h__
#define __dyn_generic_h__

/**
 * @file
 * @brief load dynamic libraries
 *
 * @code
 *  #include "dyn_generic.h"
 *
 *  #ifdef WIN32
 *  #define LIBRARY_NAME "foobar.dll"
 *  #else
 *  #define LIBRARY_NAME "foobar.so"
 *  #endif
 *
 *  void *handle;
 *  void (*p)(int, int);
 *
 *  SYS_dyn_LoadLibrary(&handle, LIBRARY_NAME);
 *  if (NULL == handle)
 *  {
 *      printf("Can't open %s", LIBRARY_NAME);
 *      return -1;
 *  }
 *
 *  // we need a cast since function_ptr is of type "void (*)(void)"
 *  // and p is of type "void (*)(int, int)"
 *  SYS_dyn_GetAddress(handle, (function_ptr*)&p, FUNCTION_NAME);
 *
 *  // we close now to not forget it after testing p value
 *  SYS_dyn_CloseLibrary(&handle);
 *
 *  if (NULL == p)
 *  {
 *      printf("function %s not found", FUNCTION_NAME);
 *      return -1;
 *  }
 *
 *  // call the function
 *  p(1, 2);
 * @endcode
 */

#ifdef __cplusplus
extern "C"
{
#endif

typedef void (*function_ptr)(void);

	/**
	 * dynamically loads a library
	 * @param handle returned handle
	 * @param library_name library file name
	 * @retval 0 if OK
	 * @retval -1 on error and *pvLHandle is set to NULL
	 */
    int SYS_dyn_LoadLibrary(void **handle, const char *library_name);

	/**
	 * close/unload a dynamically loaded library
	 * @param handle handle returned by SYS_dyn_LoadLibrary()
	 * @retval 0 if OK
	 * @retval -1 on error
	 *
	 * Side effect: *pvLHandle is set to NULL
	 */
    int SYS_dyn_CloseLibrary(void **handle);

	/**
	 * get the adsress of a function from a dynamicall loaded library
	 * @param handle handle returned by SYS_dyn_LoadLibrary()
	 * @param function_ptr address to store the function address
	 * @param function_name function name
	 * @retval 0 if OK
	 * @retval -1 on error and pvFHandle is set to NULL
	 */
    int SYS_dyn_GetAddress(void *handle, function_ptr *function_ptr,
        const char *function_name);

#ifdef __cplusplus
}
#endif
 
#endif

