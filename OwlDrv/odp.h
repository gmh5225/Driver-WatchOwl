/*++

Copyright (c) 2022 ur nan

Module Name:

    odp.h

Abstract:

    Header file for WatchOwl Driver

Author:

    Rad Kawar (rad98)		14-Nov-2022

Environment:

    Kernel mode

Revision History:

--*/

#ifndef _ODP_H
#define _ODP_H

#include "precomp.h"

/*
* Memory tag for memory blocks allocated by this driver
* This DWORD appears as 'OwlD' in a little-endian memory byte dump.
*/
#define FILTER_TAG (ULONG) 'DlwO'

#ifdef DBG
#endif 

#define DbgPrintLine(s, ...) DbgPrint("OWLDRV: " s "\n", __VA_ARGS__)

#define PAGED_PASSIVE()\
    PAGED_CODE()\
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL)

#ifdef  _WIN64
#define offsetof(s,m)   (size_t)( (ptrdiff_t)&(((s *)0)->m) )
#else
#define offsetof(s,m)   (size_t)&(((s *)0)->m)
#endif


#endif // _ODP_H