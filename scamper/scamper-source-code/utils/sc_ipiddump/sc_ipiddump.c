/*
 * sc_ipiddump
 *
 * $Id: sc_ipiddump.c,v 1.8 2015/08/27 18:28:35 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2013 The Regents of the University of California
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
  "$Id: sc_ipiddump.c,v 1.8 2015/08/27 18:28:35 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_file.h"
#include "ping/scamper_ping.h"
#include "dealias/scamper_dealias.h"
#include "mjl_list.h"
#include "utils.h"

typedef struct ipid_sample
{
  scamper_addr_t *probe_src;
  scamper_addr_t *addr;
  struct timeval  tx;
  struct timeval  rx;
  uint32_t        ipid;
} ipid_sample_t;

/* file filter */
static scamper_file_filter_t *filter;

/* the input warts files */
static char **filelist = NULL;
static int    filelist_len = 0;

static slist_t *list = NULL;

static uint32_t *userids = 0;
static int       useridc = 0;

#define OPT_USERID 0x0001

static void usage(uint32_t opt_mask)
{
  fprintf(stderr, "usage: sc_ipiddump [-?] [-U userid] <file.warts>\n");
  if(opt_mask & OPT_USERID)
    fprintf(stderr, "      -U userid to filter\n");
  return;
}

static int uint32_cmp(const void *va, const void *vb)
{
  const uint32_t a = *((uint32_t *)va);
  const uint32_t b = *((uint32_t *)vb);
  if(a < b) return -1;
  if(a > b) return  1;
  return 0;
}

static int uint32_find(uint32_t *a, size_t len, uint32_t u32)
{
  if(bsearch(&u32, a, len, sizeof(uint32_t), uint32_cmp) != NULL)
    return 1;
  return 0;
}

static int check_options(int argc, char *argv[])
{
  int ch; long lo;
  char *opts = "?U:";
  char *opt_userid = NULL;
  char *next;
  uint32_t a[256];
  int i, x;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'U':
	  opt_userid = strdup(optarg);
	  break;

	case '?':
	default:
	  usage(0xffffffff);
	  goto err;
	}
    }

  if(opt_userid != NULL)
    {
      x = 0;
      do
	{
	  string_nullterm_char(opt_userid, ',', &next);
	  if(string_tolong(opt_userid, &lo) != 0 || lo < 0 || lo > 65535)
	    {
	      usage(OPT_USERID);
	      goto err;
	    }
	  a[x++] = lo;
	  opt_userid = next;
	}
      while(opt_userid != NULL);
      if((userids = malloc(sizeof(uint32_t) * x)) == NULL)
	goto err;
      for(i=0; i<x; i++)
	userids[i] = a[i];
      useridc = x;
      qsort(userids, useridc, sizeof(uint32_t), uint32_cmp);
    }

  filelist     = argv+optind;
  filelist_len = argc-optind;

  if(filelist_len == 0)
    {
      usage(0xffffffff);
      goto err;
    }

  if(opt_userid != NULL) free(opt_userid);
  return 0;

 err:
  if(opt_userid != NULL) free(opt_userid);
  return -1;
}

static int ipid_sample_cmp(const ipid_sample_t *a, const ipid_sample_t *b)
{
  return timeval_cmp(&a->tx, &b->tx);
}

static char *ipid_sample_ipid(const ipid_sample_t *sample,char *buf,size_t len)
{
  if(SCAMPER_ADDR_TYPE_IS_IPV4(sample->addr))
    snprintf(buf, len, "%04x", sample->ipid);
  else
    snprintf(buf, len, "%08x", sample->ipid);
  return buf;
}

static void ipid_sample_free(ipid_sample_t *sample)
{
  if(sample == NULL)
    return;
  if(sample->addr != NULL)
    scamper_addr_free(sample->addr);
  if(sample->probe_src != NULL)
    scamper_addr_free(sample->probe_src);
  free(sample);
  return;
}

static int process_dealias(scamper_dealias_t *dealias)
{
  scamper_dealias_probe_t *probe;
  scamper_dealias_reply_t *reply;
  ipid_sample_t *sample;
  uint32_t i, u32;
  uint16_t j;

  if(useridc > 0 && uint32_find(userids, useridc, dealias->userid) == 0)
    return 0;

  for(i=0; i<dealias->probec; i++)
    {
      probe = dealias->probes[i];
      for(j=0; j<probe->replyc; j++)
	{
	  reply = probe->replies[j];
	  if(SCAMPER_ADDR_TYPE_IS_IPV4(reply->src))
	    u32 = reply->ipid;
	  else if(reply->flags & SCAMPER_DEALIAS_REPLY_FLAG_IPID32)
	    u32 = reply->ipid32;
	  else
	    continue;

	  if((sample = malloc_zero(sizeof(ipid_sample_t))) == NULL)
	    goto err;
	  sample->probe_src = scamper_addr_use(probe->def->src);
	  sample->addr = scamper_addr_use(reply->src);
	  sample->ipid = u32;
	  timeval_cpy(&sample->tx, &probe->tx);
	  timeval_cpy(&sample->rx, &reply->rx);

	  if(slist_tail_push(list, sample) == NULL)
	    goto err;
	}
    }

  scamper_dealias_free(dealias);
  return 0;

 err:
  scamper_dealias_free(dealias);
  return -1;
}

static int process_ping(scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply;
  ipid_sample_t *sample;
  uint16_t i;
  uint32_t u32;

  if(useridc > 0 && uint32_find(userids, useridc, ping->userid) == 0)
    return 0;

  for(i=0; i<ping->ping_sent; i++)
    {
      for(reply = ping->ping_replies[i]; reply != NULL; reply = reply->next)
	{
	  if(reply->tx.tv_sec == 0)
	    continue;

	  if(SCAMPER_ADDR_TYPE_IS_IPV4(reply->addr))
	    u32 = reply->reply_ipid;
	  else if(reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID)
	    u32 = reply->reply_ipid32;
	  else
	    continue;

	  if((sample = malloc_zero(sizeof(ipid_sample_t))) == NULL)
	    goto err;
	  sample->probe_src = scamper_addr_use(ping->src);
	  sample->addr = scamper_addr_use(reply->addr);
	  sample->ipid = u32;
	  timeval_cpy(&sample->tx, &reply->tx);
	  timeval_add_tv3(&sample->rx, &reply->tx, &reply->rtt);

	  if(slist_tail_push(list, sample) == NULL)
	    goto err;
	}
    }

  scamper_ping_free(ping);
  return 0;

 err:
  scamper_ping_free(ping);
  return -1;
}

static void process(scamper_file_t *file)
{
  void *data;
  uint16_t type;

  while(scamper_file_read(file, filter, &type, &data) == 0)
    {
      if(data == NULL) break; /* EOF */
      if(type == SCAMPER_FILE_OBJ_PING)
	process_ping(data);
      else if(type == SCAMPER_FILE_OBJ_DEALIAS)
	process_dealias(data);
    }
  scamper_file_close(file);
  return;
}

int main(int argc, char *argv[])
{
  scamper_file_t *file;
  ipid_sample_t *sample;
  uint16_t types[] = {
    SCAMPER_FILE_OBJ_PING,
    SCAMPER_FILE_OBJ_DEALIAS,
  };
  int typec = sizeof(types) / sizeof(uint16_t);
  char probe_src[128], addr[128], ipid[10];
  int i;

#ifdef _WIN32
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2,2), &wsaData);
#endif

  if(check_options(argc, argv) != 0)
    return -1;

  if((filter = scamper_file_filter_alloc(types, typec)) == NULL)
    return -1;

  if((list = slist_alloc()) == NULL)
    return -1;

  if(filelist_len != 0)
    {
      for(i=0; i<filelist_len; i++)
	{
	  if((file = scamper_file_open(filelist[i], 'r', NULL)) == NULL)
	    fprintf(stderr, "unable to open %s\n", filelist[i]);
	  else
	    process(file);
	}
    }
  else
    {
      if((file = scamper_file_openfd(STDIN_FILENO, "-", 'r', "warts")) == NULL)
	fprintf(stderr, "unable to open stdin\n");
      else
	process(file);
    }

  scamper_file_filter_free(filter);

  slist_qsort(list, (slist_cmp_t)ipid_sample_cmp);
  while((sample = slist_head_pop(list)) != NULL)
    {
      printf("%d.%06d %d.%06d %s %s %s\n",
	     (int)sample->tx.tv_sec, (int)sample->tx.tv_usec,
	     (int)sample->rx.tv_sec, (int)sample->rx.tv_usec,
	     scamper_addr_tostr(sample->probe_src,probe_src,sizeof(probe_src)),
	     scamper_addr_tostr(sample->addr, addr, sizeof(addr)),
	     ipid_sample_ipid(sample, ipid, sizeof(ipid)));
      ipid_sample_free(sample);
    }
  slist_free(list);

  return 0;
}
