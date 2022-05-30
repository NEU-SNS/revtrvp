/*
 * scamper_writebuf.c: use in combination with select to send without blocking
 *
 * $Id: scamper_writebuf.c,v 1.42 2015/08/29 22:35:57 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
 * Copyright (C) 2014      The Regents of the University of California
 * Copyright (C) 2014-2015 Matthew Luckie
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
  "$Id: scamper_writebuf.c,v 1.42 2015/08/29 22:35:57 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_writebuf.h"
#include "mjl_list.h"
#include "utils.h"

static int iov_max = -1;

/*
 * scamper_writebuf
 *
 * this is a simple struct to maintain a list of iovec structures that are
 * to be sent when the underlying fd allows.
 *
 */
struct scamper_writebuf
{
  slist_t      *iovs;
  void         *param;
  int           error;
  int           usewrite;
};

#ifndef _WIN32
static int writebuf_tx(scamper_writebuf_t *wb, int fd)
{
  struct msghdr msg;
  struct iovec *iov;
  uint8_t *bytes;
  ssize_t size;
  slist_node_t *node;
  int i, iovs;

  if((iovs = slist_count(wb->iovs)) <= 0)
    return 0;

  if(wb->usewrite != 0)
    {
      while((iov = slist_head_item(wb->iovs)) != NULL)
	{
	  if((size = write(fd, iov->iov_base, iov->iov_len)) == -1)
	    {
	      if(errno == EAGAIN || errno == EINTR)
		return 0;
	      return -1;
	    }
	  
	  if((size_t)size == iov->iov_len)
	    {
	      slist_head_pop(wb->iovs);
	      free(iov->iov_base);
	      free(iov);
	    }
	  else
	    {
	      iov->iov_len -= size;
	      bytes = (uint8_t *)iov->iov_base;
	      memmove(iov->iov_base, bytes + size, iov->iov_len);
	    }
	}

      return 0;
    }

  if(iovs > iov_max)
    iovs = iov_max;

  /*
   * if there is only one iovec, or we can't allocate an array large enough
   * for the backlog, then just send the first without allocating the
   * array.  otherwise, fill the array with the iovecs to send.
   */
  if(iovs == 1 || (iov = malloc_zero(iovs * sizeof(struct iovec))) == NULL)
    {
      iov = slist_head_item(wb->iovs);
      iovs = 1;
    }
  else
    {
      node = slist_head_node(wb->iovs);
      for(i=0; i<iovs; i++)
	{
	  assert(node != NULL);
	  memcpy(&iov[i], slist_node_item(node), sizeof(struct iovec));
	  node = slist_node_next(node);
	}
    }

  /* fill out the msghdr and set the send buf to be the iovecs */
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = iov;
  msg.msg_iovlen = iovs;
  size = sendmsg(fd, &msg, 0);

  /* if we allocated an array of iovecs, then free it now */
  if(iovs > 1)
    free(iov);

  if(size == -1)
    {
      if(errno == EAGAIN || errno == EINTR)
	return 0;
      return -1;
    }

  /* free up the iovecs that have been sent */
  while(size > 0)
    {
      node = slist_head_node(wb->iovs);
      iov = slist_node_item(node);

      /* if the whole iovec was used then it can be free'd */
      if(iov->iov_len <= (size_t)size)
	{
	  size -= iov->iov_len;
	  free(iov->iov_base);
	  free(iov);
	  slist_head_pop(wb->iovs);
	  continue;
	}

      /* if this iovec was only partially sent, then shift the vec */
      bytes = (uint8_t *)iov->iov_base;
      memmove(iov->iov_base, bytes + size, iov->iov_len - size);
      iov->iov_len -= size;
      break;
    }

  return 0;
}
#endif

#ifdef _WIN32
static int writebuf_tx(scamper_writebuf_t *wb, int fd)
{
  struct iovec *iov;
  int size;

  if(slist_count(wb->iovs) == 0)
    return 0;

  iov = slist_head_item(wb->iovs);
  if((size = send(fd, iov->iov_base, iov->iov_len, 0)) == -1)
    return -1;

  if((size_t)size == iov->iov_len)
    {
      slist_head_pop(wb->iovs);
      free(iov->iov_base);
      free(iov);
    }
  else
    {
      iov->iov_len -= size;
      memmove(iov->iov_base, (uint8_t *)iov->iov_base + size, iov->iov_len);
    }

  return 0;
}
#endif

/*
 * scamper_writebuf_write
 *
 * this function is called when the fd is ready to write to.
 */
int scamper_writebuf_write(int fd, scamper_writebuf_t *wb)
{
  if(writebuf_tx(wb, fd) != 0)
    {
      wb->error = errno;
      return -1;
    }
  return 0;
}

size_t scamper_writebuf_len(const scamper_writebuf_t *wb)
{
  slist_node_t *node = slist_head_node(wb->iovs);
  struct iovec *iov;
  size_t len = 0;

  while(node != NULL)
    {
      iov = slist_node_item(node);
      len += iov->iov_len;
      node = slist_node_next(node);
    }

  return len;
}

size_t scamper_writebuf_len2(const scamper_writebuf_t *wb,char *str,size_t len)
{
  slist_node_t *node;
  struct iovec *iov;
  size_t k = 0, off = 0;
  int c = 0;

  for(node=slist_head_node(wb->iovs); node != NULL; node=slist_node_next(node))
    {
      iov = slist_node_item(node);
      k += iov->iov_len;
      c++;
    }

  string_concat(str, len, &off, "%d,%d%s", k, c, (k != 0) ? ":" : "");
  for(node=slist_head_node(wb->iovs); node != NULL; node=slist_node_next(node))
    {
      iov = slist_node_item(node);
      string_concat(str, len, &off, " %d", iov->iov_len);
    }

  return k;
}

/*
 * scamper_writebuf_send
 *
 * register an iovec to send when it can be sent without blocking the
 * rest of scamper.
 */
int scamper_writebuf_send(scamper_writebuf_t *wb, const void *data, size_t len)
{
  struct iovec *iov = NULL;

  /* make sure there is data to send */
  if(len < 1)
    return 0;

  /*
   * an error occured last time sendmsg(2) was called which makes this
   * writebuf invalid
   */
  if(wb->error != 0)
    return -1;

  /* allocate the iovec and fill it out */
  if((iov = malloc_zero(sizeof(struct iovec))) == NULL ||
     (iov->iov_base = memdup(data, len)) == NULL)
    {
      goto err;
    }
  iov->iov_len = len;

  /* put the iovec at the tail of iovecs to send */
  if(slist_tail_push(wb->iovs, iov) == NULL)
    goto err;

  return 0;

 err:
  if(iov == NULL)
    return -1;
  if(iov->iov_base != NULL) free(iov->iov_base);
  free(iov);
  return -1;
}

void scamper_writebuf_usewrite(scamper_writebuf_t *wb)
{
  wb->usewrite = 1;
  return;
}

/*
 * scamper_writebuf_free
 *
 */
void scamper_writebuf_free(scamper_writebuf_t *wb)
{
  struct iovec *iov;

  if(wb == NULL)
    return;

  if(wb->iovs != NULL)
    {
      while((iov = slist_head_pop(wb->iovs)) != NULL)
	{
	  free(iov->iov_base);
	  free(iov);
	}
      slist_free(wb->iovs);
    }

  free(wb);
  return;
}

/*
 * scamper_writebuf_alloc
 *
 */
scamper_writebuf_t *scamper_writebuf_alloc(void)
{
  scamper_writebuf_t *wb = NULL;

  if(iov_max == -1)
    {
#ifdef IOV_MAX
      iov_max = IOV_MAX;
#elif defined(_SC_IOV_MAX)
      iov_max = sysconf(_SC_IOV_MAX);
#else
      iov_max = 1;
#endif
    }

  if((wb = malloc_zero(sizeof(scamper_writebuf_t))) == NULL ||
     (wb->iovs = slist_alloc()) == NULL)
    goto err;
  return wb;

 err:
  scamper_writebuf_free(wb);
  return NULL;
}
