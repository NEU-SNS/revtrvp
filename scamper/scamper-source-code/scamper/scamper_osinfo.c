/*
 * scamper_osinfo.c
 *
 * $Id: scamper_osinfo.c,v 1.2 2014/06/12 19:59:48 mjl Exp $
 *
 * Copyright (C) 2006 Matthew Luckie
 * Copyright (C) 2014 The Regents of the University of California
 * Author: Matthew Luckie
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_osinfo.c,v 1.2 2014/06/12 19:59:48 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_osinfo.h"
#include "utils.h"

static scamper_osinfo_t *osinfo = NULL;

const scamper_osinfo_t *scamper_osinfo_get(void)
{
  return osinfo;
}

/*
 * uname_wrap
 *
 * do some basic parsing on the output from uname
 */
#ifndef _WIN32
int scamper_osinfo_init(void)
{
  struct utsname    utsname;
  int               i;
  char             *str;

  /* call uname to get the information */
  if(uname(&utsname) < 0)
    goto err;

  /* allocate our wrapping struct */
  if((osinfo = malloc_zero(sizeof(scamper_osinfo_t))) == NULL)
    goto err;

  /* copy sysname in */
  if((osinfo->os = strdup(utsname.sysname)) == NULL)
    goto err;

  /* parse the OS name */
  if(strcasecmp(osinfo->os, "FreeBSD") == 0)
    osinfo->os_id = SCAMPER_OSINFO_OS_FREEBSD;
  else if(strcasecmp(osinfo->os, "OpenBSD") == 0)
    osinfo->os_id = SCAMPER_OSINFO_OS_OPENBSD;
  else if(strcasecmp(osinfo->os, "NetBSD") == 0)
    osinfo->os_id = SCAMPER_OSINFO_OS_NETBSD;
  else if(strcasecmp(osinfo->os, "SunOS") == 0)
    osinfo->os_id = SCAMPER_OSINFO_OS_SUNOS;
  else if(strcasecmp(osinfo->os, "Linux") == 0)
    osinfo->os_id = SCAMPER_OSINFO_OS_LINUX;
  else if(strcasecmp(osinfo->os, "Darwin") == 0)
    osinfo->os_id = SCAMPER_OSINFO_OS_DARWIN;

  /* parse the release integer string */
  str = utsname.release;
  while(*str != '\0')
    {
      if(*str == '.')
	{
	  *str = '\0';
	  osinfo->os_rel_dots++;
	}
      else if(isdigit((int)*str) == 0)
	{
	  *str = '\0';
	  break;
	}
      str++;
    }
  if((osinfo->os_rel = malloc_zero(osinfo->os_rel_dots * sizeof(long))) == NULL)
    goto err;
  str = utsname.release;
  for(i=0; i < osinfo->os_rel_dots; i++)
    {
      if(string_tolong(str, &osinfo->os_rel[i]) != 0)
	goto err;

      while(*str != '\0') str++;
      str++;
    }

  return 0;

 err:
  return -1;
}
#endif

#ifdef _WIN32
int scamper_osinfo_init(void)
{
  if((osinfo = malloc_zero(sizeof(scamper_osinfo_t))) == NULL)
    goto err;
  if((osinfo->os = strdup("Windows")) == NULL)
    goto err;
  osinfo->os_id = SCAMPER_OSINFO_OS_WINDOWS;
  return 0;

 err:
  return -1;
}
#endif

void scamper_osinfo_cleanup(void)
{
  if(osinfo == NULL)
    return;
  if(osinfo->os != NULL) free(osinfo->os);
  if(osinfo->os_rel != NULL) free(osinfo->os_rel);
  free(osinfo);
  return;
}
