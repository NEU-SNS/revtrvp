/*
 * scamper_debug.c
 *
 * $Id: scamper_debug.c,v 1.34 2012/04/05 18:00:54 mjl Exp $
 *
 * routines to reduce the impact of debugging cruft in scamper's code.
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
 * Copyright (C) 2012      Matthew Luckie
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
  "$Id: scamper_debug.c,v 1.34 2012/04/05 18:00:54 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_debug.h"
#include "scamper_privsep.h"
#include "utils.h"

#ifndef WITHOUT_DEBUGFILE
static FILE *debugfile = NULL;
#endif

static char *timestamp_str(char *buf, const size_t len)
{
  struct timeval  tv;
  struct tm      *tm;
  int             ms;
  time_t          t;

  buf[0] = '\0';
  gettimeofday_wrap(&tv);
  t = tv.tv_sec;
  if((tm = localtime(&t)) == NULL) return buf;

  ms = tv.tv_usec / 1000;
  snprintf(buf, len, "[%02d:%02d:%02d:%03d] ",
	   tm->tm_hour, tm->tm_min, tm->tm_sec, ms);

  return buf;
}

#ifndef NDEBUG
void __scamper_assert(const char *file, int line, const char *func,
		      const char *expr, void *data)
{
  char ts[16];

  timestamp_str(ts, sizeof(ts));

  fprintf(stderr, "%s assertion failed: %s:%d %s `%s'\n",
	  ts, file, line, func, expr);
  fflush(stderr);

#ifndef WITHOUT_DEBUGFILE
  if(debugfile != NULL)
    {
      fprintf(debugfile, "%s assertion failed: %s:%d %s `%s'\n",
	      ts, file, line, func, expr);
      fflush(debugfile);
    }
#endif

  abort();
  return;
}
#endif

static char *error_str(int e, char *(*error_itoa)(int), char *buf, size_t len)
{
  char *str;

  if(error_itoa == NULL || (str = error_itoa(e)) == NULL)
    {
      buf[0] = '\0';
      return buf;
    }

  snprintf(buf, len, ": %s", str);
  return buf;
}

/*
 * printerror
 *
 * format a nice and consistent error string using the errno to string
 * conversion utilities and the arguments supplied
 */
void printerror(const int ecode, char *(*error_itoa)(int),
		const char *func, const char *format, ...)
{
  char     message[512];
  char     err[128];
  char     ts[16];
  char     fs[64];
  va_list  ap;

  va_start(ap, format);
  vsnprintf(message, sizeof(message), format, ap);
  va_end(ap);

  error_str(ecode, error_itoa, err, sizeof(err));
  timestamp_str(ts, sizeof(ts));

  if(func != NULL) snprintf(fs, sizeof(fs), "%s: ", func);
  else             fs[0] = '\0';

  fprintf(stderr, "%s%s%s%s\n", ts, fs, message, err);
  fflush(stderr);

#ifndef WITHOUT_DEBUGFILE
  if(debugfile != NULL)
    {
      fprintf(debugfile, "%s%s%s%s\n", ts, fs, message, err);
      fflush(debugfile);
    }
#endif

  return;
}

#ifdef HAVE_SCAMPER_DEBUG
void scamper_debug(const char *func, const char *format, ...)
{
  char     message[512];
  va_list  ap;
  char     ts[16];
  char     fs[64];

#if !defined(WITHOUT_DEBUGFILE) && defined(NDEBUG)
  if(debugfile == NULL)
    return;
#endif

  assert(format != NULL);

  va_start(ap, format);
  vsnprintf(message, sizeof(message), format, ap);
  va_end(ap);

  timestamp_str(ts, sizeof(ts));

  if(func != NULL) snprintf(fs, sizeof(fs), "%s: ", func);
  else             fs[0] = '\0';

#ifndef NDEBUG
  fprintf(stderr, "%s%s%s\n", ts, fs, message);
  fflush(stderr);
#endif

#ifndef WITHOUT_DEBUGFILE
  if(debugfile != NULL)
    {
      fprintf(debugfile, "%s%s%s\n", ts, fs, message);
      fflush(debugfile);
    }
#endif

  return;
}
#endif

#ifndef WITHOUT_DEBUGFILE
int scamper_debug_open(const char *file)
{
  mode_t mode;
  int flags, fd;

#if defined(WITHOUT_PRIVSEP) && !defined(_WIN32)
  uid_t uid = getuid();
#endif

#ifndef _WIN32
  mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
#else
  mode = _S_IREAD | _S_IWRITE;
#endif

  if(scamper_option_debugfileappend() == 0)
    flags = O_WRONLY | O_CREAT | O_TRUNC;
  else
    flags = O_WRONLY | O_CREAT | O_APPEND;

#ifndef WITHOUT_PRIVSEP
  fd = scamper_privsep_open_file(file, flags, mode);
#else
  fd = open(file, flags, mode);
#endif

  if(fd == -1)
    {
      printerror(errno, strerror, __func__,
		 "could not open debugfile %s", file);
      return -1;
    }

  if((debugfile = fdopen(fd, "a")) == NULL)
    {
      printerror(errno, strerror, __func__,
		 "could not fdopen debugfile %s", file);
      return -1;
    }

#if defined(WITHOUT_PRIVSEP) && !defined(_WIN32)
  if(uid != geteuid() && fchown(fd, uid, -1) != 0)
    {
      printerror(errno, strerror, __func__, "could not fchown");
    }
#endif

  return 0;
}

void scamper_debug_close()
{
  if(debugfile != NULL)
    {
      fclose(debugfile);
      debugfile = NULL;
    }
  return;
}
#endif
