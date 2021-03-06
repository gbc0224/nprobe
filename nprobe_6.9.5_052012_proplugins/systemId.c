/*
 *
 *       Copyright (C) 2002-12 Luca Deri <deri@ntop.org>
 *
 *                     http://www.ntop.org/
 *
 */

#define _NPROBE_H_ /* Trick */

#include "nprobe.h"
#include "config.h"

#ifdef HAVE_LICENSE

#ifdef WIN32
#include "private/license/systemId_win32.c"
#else
#include "private/license/systemId.c"
#endif

#else

char* getSystemId() { return(""); }

#endif

