/*
 * sc_remoted
 *
 * $Id: sc_remoted.c,v 1.34 2015/09/15 02:12:30 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2014-2015 Matthew Luckie
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
  "$Id: sc_remoted.c,v 1.34 2015/09/15 02:12:30 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_linepoll.h"
#include "scamper_writebuf.h"
#include "mjl_splaytree.h"
#include "mjl_list.h"
#include "utils.h"

/*
 * sc_unit
 *
 * this generic structure says what kind of node is pointed to, and is
 * used to help garbage collect with kqueue / epoll.
 */
typedef struct sc_unit
{
  void               *data;
  dlist_t            *list; /* list == gclist if on that list */
  dlist_node_t       *node;
  uint8_t             type;
  uint8_t             gc;
} sc_unit_t;

#define UNIT_TYPE_NEWCONN 0
#define UNIT_TYPE_CLIENT  1
#define UNIT_TYPE_MASTER  2

/*
 * sc_fd
 *
 * this structure associates a file descriptor with a data pointer, as
 * well as information about what type the fd is and any current
 * state.
 */
typedef struct sc_fd
{
  int                 fd;
  sc_unit_t          *unit;
  uint8_t             type;
  uint8_t             flags;
} sc_fd_t;

#define FD_TYPE_SERVER      0
#define FD_TYPE_NEWCONN     1
#define FD_TYPE_CLIENT_INET 2
#define FD_TYPE_CLIENT_UNIX 3
#define FD_TYPE_MASTER_INET 4
#define FD_TYPE_MASTER_UNIX 5

#define FD_FLAG_READ        1
#define FD_FLAG_WRITE       2

/*
 * sc_inet
 *
 * this structure is used throughout to handle IP sockets,
 * possibly with TLS.
 */
typedef struct sc_inet
{
  sc_fd_t             fd;
  scamper_linepoll_t *lp;
  scamper_writebuf_t *wb;

#ifdef HAVE_OPENSSL
  int                 mode;
  SSL                *ssl;
  BIO                *rbio;
  BIO                *wbio;
#endif
} sc_inet_t;

/*
 * sc_master_t
 *
 * this structure holds a mapping between a remote scamper process
 * that is willing to be driven and a local unix domain socket where
 * local processes can connect.  it also includes a list of all
 * clients connected using the socket.
 */
typedef struct sc_master
{
  sc_unit_t          *unit;
  char               *name;
  sc_inet_t          *inet;
  sc_fd_t            *unix_fd;
  dlist_t            *clients;
  dlist_node_t       *node;
} sc_master_t;

/*
 * sc_client_t
 *
 * this structure holds a mapping between a local process that wants
 * to drive a remote scamper, and a socket corresponding to that
 * instance.
 */
typedef struct sc_client
{
  sc_unit_t          *unit;
  sc_inet_t          *inet;
  sc_fd_t            *unix_fd;
  scamper_linepoll_t *unix_lp;
  scamper_writebuf_t *unix_wb;
  sc_master_t        *master;
  dlist_node_t       *node;
} sc_client_t;

/*
 * sc_newconn
 *
 * a new connection has arrived.  we do not know whether it is a remote
 * scamper process offering to call back on demand, or if it is a call
 * back process.  so we have to wait and see, but only until the time
 * specified.
 */
typedef struct sc_newconn
{
  sc_unit_t          *unit;
  sc_inet_t          *inet;
  struct timeval      tv;
  dlist_node_t       *node;
} sc_newconn_t;

/*
 * sc_magic_t
 *
 * a mapping between a unix FD and a magic value expected in a callback
 */
typedef struct sc_magic
{
  char               *magic;
  sc_master_t        *master;
  int                 unix_fd;
  splaytree_node_t   *tree_node;
} sc_magic_t;

#define OPT_HELP    0x0001
#define OPT_UNIX    0x0002
#define OPT_PORT    0x0004
#define OPT_DAEMON  0x0008
#define OPT_IPV4    0x0010
#define OPT_IPV6    0x0020
#define OPT_OPTION  0x0040
#define OPT_TLSCERT 0x0080
#define OPT_TLSPRIV 0x0100
#define OPT_ALL     0xffff

static uint16_t     options        = 0;
static char        *unix_name      = NULL;
static int          port           = 0;
static dlist_t     *mslist         = NULL;
static dlist_t     *nclist         = NULL;
static dlist_t     *gclist         = NULL;
static splaytree_t *magictree      = NULL;
static int          stop           = 0;
static int          opt_keepalives = 0;
static int          opt_select     = 0;
static int          serversockets[2];

#if defined(HAVE_EPOLL)
static int          epfd           = -1;
#elif defined(HAVE_KQUEUE)
static int          kqfd           = -1;
#endif

#ifdef HAVE_OPENSSL
static SSL_CTX     *tls_ctx = NULL;
static char        *tls_certfile   = NULL;
static char        *tls_privfile   = NULL;
#define SSL_MODE_ACCEPT      0x00
#define SSL_MODE_ESTABLISHED 0x01
#define SSL_MODE_SHUTDOWN    0x02
#endif

/*
 * sc_unit_gc_t:
 *
 * method to cleanup tasks when its time to garbage collect
 */
typedef void (*sc_unit_gc_t)(void *);
static void sc_newconn_free(sc_newconn_t *);
static void sc_client_free(sc_client_t *);
static void sc_master_free(sc_master_t *);
static const sc_unit_gc_t unit_gc[] = {
  (sc_unit_gc_t)sc_newconn_free,     /* UNIT_TYPE_NEWCONN */
  (sc_unit_gc_t)sc_client_free,      /* UNIT_TYPE_CLIENT */
  (sc_unit_gc_t)sc_master_free,      /* UNIT_TYPE_MASTER */
};

#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
typedef void (*sc_fd_cb_t)(void *);
static void sc_newconn_inet_read(sc_newconn_t *);
static void sc_newconn_inet_write(sc_newconn_t *);
static void sc_client_inet_read(sc_client_t *);
static void sc_client_inet_write(sc_client_t *);
static void sc_client_unix_read(sc_client_t *);
static void sc_client_unix_write(sc_client_t *);
static void sc_master_inet_read(sc_master_t *);
static void sc_master_inet_write(sc_master_t *);
static void sc_master_unix_accept(sc_master_t *);

static const sc_fd_cb_t read_cb[] = {
  NULL,                              /* FD_TYPE_SERVER */
  (sc_fd_cb_t)sc_newconn_inet_read,  /* FD_TYPE_NEWCONN */
  (sc_fd_cb_t)sc_client_inet_read,   /* FD_TYPE_CLIENT_INET */
  (sc_fd_cb_t)sc_client_unix_read,   /* FD_TYPE_CLIENT_UNIX */
  (sc_fd_cb_t)sc_master_inet_read,   /* FD_TYPE_MASTER_INET */
  (sc_fd_cb_t)sc_master_unix_accept, /* FD_TYPE_MASTER_UNIX */
};
static const sc_fd_cb_t write_cb[] = {
  NULL,                              /* FD_TYPE_SERVER */
  (sc_fd_cb_t)sc_newconn_inet_write, /* FD_TYPE_NEWCONN */
  (sc_fd_cb_t)sc_client_inet_write,  /* FD_TYPE_CLIENT_INET */
  (sc_fd_cb_t)sc_client_unix_write,  /* FD_TYPE_CLIENT_UNIX */
  (sc_fd_cb_t)sc_master_inet_write,  /* FD_TYPE_MASTER_INET */
  NULL,                              /* FD_TYPE_MASTER_UNIX */
};
#endif

static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
	  "usage: sc_remoted [-?46D] [-O option] [-P port] [-U unix]\n"
#ifdef HAVE_OPENSSL
	  "                  [-c certfile] [-p privfile]\n"
#endif
	  );

  if(opt_mask == 0)
    {
      fprintf(stderr, "\n     sc_remoted -?\n\n");
      return;
    }

  if(opt_mask & OPT_DAEMON)
    fprintf(stderr, "     -D operate as a daemon\n");

  if(opt_mask & OPT_OPTION)
    {
      fprintf(stderr, "     -O options\n");
      fprintf(stderr, "        tka: use tcp keepalives\n");
      fprintf(stderr, "        select: use select\n");
    }
  
  if(opt_mask & OPT_PORT)
    fprintf(stderr, "     -P port to accept remote scamper connections\n");

  if(opt_mask & OPT_UNIX)
    fprintf(stderr, "     -U directory for unix domain sockets\n");

#ifdef HAVE_OPENSSL
  if(opt_mask & OPT_TLSCERT)
    fprintf(stderr, "     -c server certificate in PEM format\n");
  if(opt_mask & OPT_TLSPRIV)
    fprintf(stderr, "     -p private key in PEM format\n");
#endif

  return;
}

static int check_options(int argc, char *argv[])
{
  char *opts = "?46DO:P:c:p:U:", *opt_port = NULL;
  long lo;
  int ch;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case '4':
	  options |= OPT_IPV4;
	  break;

	case '6':
	  options |= OPT_IPV6;
	  break;

	case 'D':
	  options |= OPT_DAEMON;
	  break;

	case 'O':
	  if(strcasecmp(optarg, "tka") == 0)
	    opt_keepalives = 1;
	  else if(strcasecmp(optarg, "select") == 0)
	    opt_select = 1;
	  else
	    {
	      usage(OPT_ALL);
	      return -1;
	    }
	  break;
	  
	case 'P':
	  opt_port = optarg;
	  break;

#ifdef HAVE_OPENSSL
	case 'c':
	  tls_certfile = optarg;
	  options |= OPT_TLSCERT;
	  break;

	case 'p':
	  tls_privfile = optarg;
	  options |= OPT_TLSPRIV;
	  break;
#endif

	case 'U':
	  unix_name = optarg;
	  break;

	case '?':
	default:
	  usage(OPT_ALL);
	  return -1;
	}
    }

  if((options & (OPT_IPV4|OPT_IPV6)) == 0)
    options |= (OPT_IPV4 | OPT_IPV6);

  if(unix_name == NULL || opt_port == NULL)
    {
      usage(OPT_PORT|OPT_UNIX);
      return -1;
    }

#ifdef HAVE_OPENSSL
  if((options & (OPT_TLSCERT|OPT_TLSPRIV)) != 0 &&
     (options & (OPT_TLSCERT|OPT_TLSPRIV)) != (OPT_TLSCERT|OPT_TLSPRIV))
    {
      usage(OPT_TLSCERT|OPT_TLSPRIV);
      return -1;
    }
#endif
  
  if(string_tolong(opt_port, &lo) != 0 || lo < 1 || lo > 65535)
    {
      usage(OPT_PORT);
      return -1;
    }
  port = lo;

  return 0;
}

static int socket_tka(int s)
{
  unsigned int ui;
  int opt;

  opt = 1;
  if(setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *)&opt, sizeof(opt)) != 0)
    {
      fprintf(stderr, "could not set SO_KEEPALIVE: %s\n", strerror(errno));
      return -1;
    }
  ui = 60 * 2;
#if defined(TCP_KEEPIDLE)
  if(setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, (char *)&ui, sizeof(ui)) != 0)
    {
      fprintf(stderr, "could not set TCP_KEEPIDLE: %s\n", strerror(errno));
      return -1;
    }
#elif defined(TCP_KEEPALIVE)
  if(setsockopt(s, IPPROTO_TCP, TCP_KEEPALIVE, (char *)&ui, sizeof(ui)) != 0)
    {
      fprintf(stderr, "could not set TCP_KEEPALIVE: %s\n", strerror(errno));
      return -1;
    }
#else
#error "unknown socket option for TCP keepalives"
#endif

  ui = 60 * 2;
  if(setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, (char *)&ui, sizeof(ui)) != 0)
    {
      fprintf(stderr, "could not set TCP_KEEPINTVL: %s\n", strerror(errno));
      return -1;
    }
  return 0;
}

#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
static int sc_fd_read_add(sc_fd_t *fd)
{
#if defined(HAVE_EPOLL)
  struct epoll_event ev;
#else
  struct kevent kev;
#endif

  if((fd->flags & FD_FLAG_READ) != 0)
    return 0;
  fd->flags |= FD_FLAG_READ;

#if defined(HAVE_EPOLL)
  ev.data.ptr = fd;
  ev.events = EPOLLIN;
  if(epoll_ctl(epfd, EPOLL_CTL_ADD, fd->fd, &ev) != 0)
    return -1;
#else
  EV_SET(&kev, fd->fd, EVFILT_READ, EV_ADD, 0, 0, fd);
  if(kevent(kqfd, &kev, 1, NULL, 0, NULL) != 0)
    return -1;
#endif
  return 0;
}

static int sc_fd_write_add(sc_fd_t *fd)
{
#if defined(HAVE_EPOLL)
  struct epoll_event ev;
#else
  struct kevent kev;
#endif

  if((fd->flags & FD_FLAG_WRITE) != 0)
    return 0;
  fd->flags |= FD_FLAG_WRITE;

#if defined(HAVE_EPOLL)
  ev.data.ptr = fd;
  ev.events = EPOLLIN | EPOLLOUT;
  if(epoll_ctl(epfd, EPOLL_CTL_MOD, fd->fd, &ev) != 0)
    return -1;
#else
  EV_SET(&kev, fd->fd, EVFILT_WRITE, EV_ADD, 0, 0, fd);
  if(kevent(kqfd, &kev, 1, NULL, 0, NULL) != 0)
    return -1;
#endif
  return 0;
}

static int sc_fd_write_del(sc_fd_t *fd)
{
#if defined(HAVE_EPOLL)
  struct epoll_event ev;
#else
  struct kevent kev;
#endif

  if((fd->flags & FD_FLAG_WRITE) == 0)
    return 0;
  fd->flags &= ~(FD_FLAG_WRITE);

#if defined(HAVE_EPOLL)
  ev.data.ptr = fd;
  ev.events = EPOLLIN; /* always listen for read events */
  if(epoll_ctl(epfd, EPOLL_CTL_MOD, fd->fd, &ev) != 0)
    return -1;
#else
  EV_SET(&kev, fd->fd, EVFILT_WRITE, EV_DELETE, 0, 0, fd);
  if(kevent(kqfd, &kev, 1, NULL, 0, NULL) != 0)
    return -1;
#endif
  return 0;
}
#endif

#ifdef HAVE_OPENSSL
static int ssl_want_read(sc_inet_t *in)
{
  uint8_t buf[1024];
  int pending, rc, size, off = 0;

  if((pending = BIO_pending(in->wbio)) < 0)
    return -1;

  while(off < pending)
    {
      if(pending - off > sizeof(buf))
	size = sizeof(buf);
      else
	size = pending - off;

      if((rc = BIO_read(in->wbio, buf, size)) <= 0)
	{
	  if(BIO_should_retry(in->wbio) == 0)
	    fprintf(stderr, "%s: BIO_read should not retry\n", __func__);
	  else
	    fprintf(stderr, "%s: BIO_read returned %d\n", __func__, rc);
	  return -1;
	}
      off += rc;

      scamper_writebuf_send(in->wb, buf, rc);
      sc_fd_write_add(&in->fd);
    }

  return pending;
}
#endif

static void sc_fd_close(sc_fd_t *sfd)
{
  if(sfd == NULL)
    return;
  if(sfd->fd != -1)
    close(sfd->fd);
  sfd->fd = -1;
  return;
}

static void sc_fd_free(sc_fd_t *sfd)
{
  if(sfd == NULL)
    return;
  if(sfd->fd != -1)
    close(sfd->fd);
  free(sfd);
  return;
}

static sc_fd_t *sc_fd_alloc(int fd, uint8_t type, sc_unit_t *unit)
{
  sc_fd_t *sfd;
  if((sfd = malloc_zero(sizeof(sc_fd_t))) == NULL)
    return NULL;
  sfd->fd = fd;
  sfd->type = type;
  sfd->unit = unit;
  return sfd;
}

static void sc_unit_onremove(sc_unit_t *scu)
{
  scu->node = NULL;
  scu->list = NULL;
  return;
}

static void sc_unit_gc(sc_unit_t *scu)
{
  if(scu->gc != 0)
    return;
  scu->gc = 1;
  dlist_node_tail_push(gclist, scu->node);
  scu->list = gclist;
  return;
}

static void sc_unit_free(sc_unit_t *scu)
{
  if(scu == NULL)
    return;
  if(scu->node != NULL)
    dlist_node_pop(scu->list, scu->node);
  free(scu);
  return;
}

static sc_unit_t *sc_unit_alloc(uint8_t type, void *data)
{
  sc_unit_t *scu;
  if((scu = malloc_zero(sizeof(sc_unit_t))) == NULL ||
     (scu->node = dlist_node_alloc(scu)) == NULL)
    {
      if(scu != NULL) sc_unit_free(scu);
      return NULL;
    }
  scu->type = type;
  scu->data = data;
  return scu;
}

static void sc_inet_free(sc_inet_t *in)
{
  if(in == NULL)
    return;

  if(in->fd.fd != -1) close(in->fd.fd);
  if(in->lp != NULL) scamper_linepoll_free(in->lp, 0);
  if(in->wb != NULL) scamper_writebuf_free(in->wb);

#ifdef HAVE_OPENSSL
  if(in->ssl != NULL)
    {
      SSL_free(in->ssl);
    }
  else
    {
      if(in->wbio != NULL)
	BIO_free(in->wbio);
      if(in->rbio != NULL)
	BIO_free(in->rbio);
    }
#endif

  free(in);
  return;
}

/*
 * sc_inet_alloc
 *
 * given an fd, wrap structure around it, including TLS if used.
 */
static sc_inet_t *sc_inet_alloc(int fd)
{
  sc_inet_t *in;

#ifdef HAVE_OPENSSL
  int rc;
#endif

  if((in = malloc_zero(sizeof(sc_inet_t))) == NULL)
    return NULL;
  in->fd.fd = -1;

  if((in->lp = scamper_linepoll_alloc(NULL, NULL)) == NULL)
    {
      fprintf(stderr,"%s: could not alloc lp: %s\n",__func__,strerror(errno));
      goto err;
    }

  if((in->wb = scamper_writebuf_alloc()) == NULL)
    {
      fprintf(stderr,"%s: could not alloc wb: %s\n",__func__,strerror(errno));
      goto err;
    }

#ifdef HAVE_OPENSSL
  if(tls_certfile != NULL)
    {
      if((in->wbio = BIO_new(BIO_s_mem())) == NULL ||
	 (in->rbio = BIO_new(BIO_s_mem())) == NULL ||
	 (in->ssl = SSL_new(tls_ctx)) == NULL)
	{
	  fprintf(stderr, "%s: could not alloc SSL\n", __func__);
	  goto err;
	}
      SSL_set_bio(in->ssl, in->rbio, in->wbio);
      SSL_set_accept_state(in->ssl);
      rc = SSL_accept(in->ssl);
      assert(rc == -1);
      if((rc = SSL_get_error(in->ssl, rc)) != SSL_ERROR_WANT_READ)
	{
	  fprintf(stderr, "%s: unexpected %d from SSL_accept\n", __func__, rc);
	  goto err;
	}
      if(ssl_want_read(in) < 0)
	goto err;
    }
#endif

  in->fd.fd = fd;
  return in;

 err:
  if(in != NULL) sc_inet_free(in);
  return NULL;
}

static int sc_inet_send(sc_inet_t *in, void *ptr, size_t len)
{
#ifdef HAVE_OPENSSL
  if(in->ssl != NULL)
    {
      SSL_write(in->ssl, ptr, len);
      if(ssl_want_read(in) < 0)
	return -1;
      return 0;
    }
#endif
  scamper_writebuf_send(in->wb, ptr, len);
  sc_fd_write_add(&in->fd);
  return 0;
}

static int sc_inet_read(sc_inet_t *in)
{
  ssize_t rrc;
  uint8_t buf[4096];

#ifdef HAVE_OPENSSL
  int rc;
#endif

  if((rrc = read(in->fd.fd, buf, sizeof(buf))) < 0)
    {
      if(errno == EAGAIN || errno == EINTR)
	return 0;
      fprintf(stderr, "%s: read failed: %s\n", __func__, strerror(errno));
      return -1;
    }

  if(rrc == 0)
    {
      fprintf(stderr, "%s: disconnected\n", __func__);
      return -1;
    }

#ifdef HAVE_OPENSSL
  if(in->ssl != NULL)
    {
      BIO_write(in->rbio, buf, rrc);
      if(in->mode == SSL_MODE_ACCEPT)
	{
	  if((rc = SSL_accept(in->ssl)) == 0)
	    {
	      fprintf(stderr, "%s: SSL_accept returned zero: %d\n",
		      __func__, SSL_get_error(in->ssl, rc));
	      ERR_print_errors_fp(stderr);
	      return -1;
	    }
	  else if(rc == 1)
	    {
	      in->mode = SSL_MODE_ESTABLISHED;
	      if(ssl_want_read(in) < 0)
		return -1;
	    }
	  else if(rc < 0)
	    {
	      rc = SSL_get_error(in->ssl, rc);
	      fprintf(stderr, "%s: SSL_accept %d\n", __func__, rc);
	      if(rc == SSL_ERROR_WANT_READ)
		{
		  if(ssl_want_read(in) < 0)
		    return -1;
		}
	      else if(rc != SSL_ERROR_WANT_WRITE)
		{
		  fprintf(stderr, "%s: mode accept rc %d\n", __func__, rc);
		  return -1;
		}
	    }
	}
      else if(in->mode == SSL_MODE_ESTABLISHED)
	{
	  while((rc = SSL_read(in->ssl, buf, sizeof(buf))) > 0)
	    scamper_linepoll_handle(in->lp, buf, (size_t)rc);
	  if(rc < 0)
	    {
	      if((rc = SSL_get_error(in->ssl, rc)) == SSL_ERROR_WANT_READ)
		{
		  if(ssl_want_read(in) < 0)
		    return -1;
		}
	      else if(rc != SSL_ERROR_WANT_WRITE)
		{
		  fprintf(stderr, "%s: mode estab rc %d\n", __func__, rc);
		  return -1;
		}
	    }
	}
      fprintf(stderr, "%s: mode %d bye\n", __func__, in->mode);
      return 0;
    }
#endif

  scamper_linepoll_handle(in->lp, buf, (size_t)rrc);
  return 0;
}

static int sc_magic_cmp(const sc_magic_t *a, const sc_magic_t *b)
{
  return strcmp(a->magic, b->magic);
}

static sc_magic_t *sc_magic_find(char *magic)
{
  sc_magic_t fm; fm.magic = magic;
  return (sc_magic_t *)splaytree_find(magictree, &fm);
}

static void sc_magic_free(sc_magic_t *mg)
{
  if(mg == NULL)
    return;
  if(mg->unix_fd != -1) close(mg->unix_fd);
  if(mg->tree_node != NULL) splaytree_remove_node(magictree, mg->tree_node);
  if(mg->magic != NULL) free(mg->magic);
  free(mg);
  return;
}

static sc_magic_t *sc_magic_alloc(const char *magic)
{
  sc_magic_t *mg;
  if((mg = malloc_zero(sizeof(sc_magic_t))) == NULL ||
     (mg->magic = strdup(magic)) == NULL)
    {
      sc_magic_free(mg);
      return NULL;
    }
  return mg;
}

/*
 * sc_client_inet_write
 *
 * we can now write to the client's IP socket without blocking, so do so.
 */
static void sc_client_inet_write(sc_client_t *cn)
{
  if(scamper_writebuf_write(cn->inet->fd.fd, cn->inet->wb) != 0)
    {
      sc_unit_gc(cn->unit);
      return;
    }

#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
  /* if nothing more to write to the inet socket, then remove from epoll */
  if(scamper_writebuf_len(cn->inet->wb) == 0 &&
     sc_fd_write_del(&cn->inet->fd) != 0)
    {
      sc_unit_gc(cn->unit);
      return;
    }
#endif

  return;
}

/*
 * sc_client_inet_lp
 *
 * the remote scamper process has something to relay to the local client
 * process connected by a unix domain socket.
 */
static int sc_client_inet_lp(sc_client_t *cn, uint8_t *buf, size_t len)
{
  if(scamper_writebuf_send(cn->unix_wb, buf, len) != 0 ||
     scamper_writebuf_send(cn->unix_wb, "\n", 1) != 0)
    sc_unit_gc(cn->unit);
  sc_fd_write_add(cn->unix_fd);
  return 0;
}

/*
 * sc_client_inet_read
 *
 * the remote scamper process has something to relay to the local client
 * process connected by a unix domain socket.
 */
static void sc_client_inet_read(sc_client_t *cn)
{
  if(sc_inet_read(cn->inet) != 0)
    {
      sc_fd_close(&cn->inet->fd);
      if(scamper_writebuf_len(cn->unix_wb) > 0)
	return;
      sc_unit_gc(cn->unit);
    }
  return;
}

/*
 * sc_client_unix_write
 *
 * we can write to the unix fd without blocking, so do so.
 */
static void sc_client_unix_write(sc_client_t *cn)
{
  size_t wblen;
  
  if(scamper_writebuf_write(cn->unix_fd->fd, cn->unix_wb) != 0)
    {
      sc_unit_gc(cn->unit);
      return;
    }

  wblen = scamper_writebuf_len(cn->unix_wb);
  
#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
  if(wblen == 0 && sc_fd_write_del(cn->unix_fd) != 0)
    {
      sc_unit_gc(cn->unit);
      return;
    }
#endif

  if(wblen == 0 && cn->inet->fd.fd == -1)
    {
      sc_unit_gc(cn->unit);
      return;
    }
  
  return;
}

/*
 * sc_client_unix_lp
 *
 * read whatever the local client process wants to relay to a remote
 * scamper process, line by line, and take appropriate action.
 */
static int sc_client_unix_lp(sc_client_t *cn, uint8_t *buf, size_t len)
{
  if(sc_inet_send(cn->inet, buf, len) != 0 ||
     sc_inet_send(cn->inet, "\n", 1) != 0)
    sc_unit_gc(cn->unit);
  return 0;
}

/*
 * sc_client_unix_read
 *
 * a local client process has written to a unix domain socket, which
 * we will process line by line.
 */
static void sc_client_unix_read(sc_client_t *cn)
{
  ssize_t rc;
  uint8_t buf[4096];
  if((rc = read(cn->unix_fd->fd, buf, sizeof(buf))) < 0)
    {
      if(errno != EAGAIN && errno != EINTR)
	sc_unit_gc(cn->unit);
      return;
    }
  if(rc == 0)
    {
      sc_unit_gc(cn->unit);
      return;
    }
  scamper_linepoll_handle(cn->unix_lp, buf, (size_t)rc);
  return;
}

static void sc_client_free(sc_client_t *cn)
{
  if(cn == NULL)
    return;
  if(cn->master != NULL && cn->node != NULL)
    dlist_node_pop(cn->master->clients, cn->node);
  if(cn->unix_fd != NULL) sc_fd_free(cn->unix_fd);
  if(cn->unix_lp != NULL) scamper_linepoll_free(cn->unix_lp, 0);
  if(cn->unix_wb != NULL) scamper_writebuf_free(cn->unix_wb);
  if(cn->inet != NULL) sc_inet_free(cn->inet);
  if(cn->unit != NULL) sc_unit_free(cn->unit);
  free(cn);
  return;
}

static void sc_master_onremove(sc_master_t *ms)
{
  ms->node = NULL;
  return;
}

static void sc_master_clients_onremove(sc_client_t *cn)
{
  cn->node = NULL;
  return;
}

/*
 * sc_master_inet_send
 *
 * transparently handle sending when an SSL socket could be used.
 */
static int sc_master_inet_send(sc_master_t *ms, void *ptr, size_t len)
{
  return sc_inet_send(ms->inet, ptr, len);
}

static void sc_master_inet_write(sc_master_t *ms)
{
  if(scamper_writebuf_write(ms->inet->fd.fd, ms->inet->wb) != 0)
    {
      sc_unit_gc(ms->unit);
      return;
    }

#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
  if(scamper_writebuf_len(ms->inet->wb) == 0 &&
     sc_fd_write_del(&ms->inet->fd) != 0)
    {
      sc_unit_gc(ms->unit);
      return;
    }
#endif
  return;
}

/*
 * sc_master_inet_lp
 *
 * linepoll structure for reading the keepalive messages.
 */
static int sc_master_inet_lp(void *param, uint8_t *buf, size_t len)
{
  return 0;
}

/*
 * sc_master_inet_read
 *
 * the remote scamper process has sent a keepalive message.  deal with
 * it using the linepoll code.
 */
static void sc_master_inet_read(sc_master_t *ms)
{
  if(sc_inet_read(ms->inet) != 0)
    sc_unit_gc(ms->unit);
  return;
}

/*
 * sc_master_unix_accept
 *
 * a local process has connected to the unix domain socket that
 * corresponds to a remote scamper process.  accept the socket and
 * cause the remote scamper process to call back.
 */
static void sc_master_unix_accept(sc_master_t *ms)
{
  struct sockaddr_storage ss;
  socklen_t socklen = sizeof(ss);
  sc_magic_t *mg = NULL;
  uint32_t u32;
  size_t off = 0;
  char tmp[32], buf[32];
  int i, s = -1;

  if((s = accept(ms->unix_fd->fd, (struct sockaddr *)&ss, &socklen)) == -1)
    {
      fprintf(stderr,"%s: no accept: %s\n", __func__, strerror(errno));
      goto err;
    }

  for(i=0; i<100; i++)
    {
      if(random_u32(&u32) != 0)
	goto err;
      snprintf(tmp, sizeof(tmp), "%u", u32);
      if(sc_magic_find(tmp) == NULL)
	break;
    }

  if((mg = sc_magic_alloc(tmp)) == NULL)
    goto err;
  mg->master = ms;
  mg->unix_fd = s; s = -1;
  if((mg->tree_node = splaytree_insert(magictree, mg)) == NULL)
    goto err;

  string_concat(buf, sizeof(buf), &off, "%s\n", tmp);
  if(sc_master_inet_send(ms, buf, off) != 0)
    goto err;
  return;

 err:
  if(mg != NULL) sc_magic_free(mg);
  if(s != -1) close(s);
  return;
}

/*
 * sc_master_free
 *
 * clean up the sc_master_t.
 */
static void sc_master_free(sc_master_t *ms)
{
  char filename[65535];

  if(ms == NULL)
    return;

  /*
   * if unix_fd is not null, it is our responsibility to both close
   * the fd, and to unlink the socket from the file system
   */
  if(ms->unix_fd != NULL)
    {
      sc_fd_free(ms->unix_fd);
      snprintf(filename, sizeof(filename), "%s/%s", unix_name, ms->name);
      unlink(filename);
    }

  if(ms->clients != NULL)
    dlist_free_cb(ms->clients, (dlist_free_t)sc_client_free);

  if(ms->unit != NULL) sc_unit_free(ms->unit);
  if(ms->inet != NULL) sc_inet_free(ms->inet);
  if(ms->name != NULL) free(ms->name);
  if(ms->node != NULL) dlist_node_pop(mslist, ms->node);
  free(ms);
  return;
}

/*
 * sc_newconn_master
 *
 * a remote scamper connection has written an entire line and is going
 * to be a master control socket.  create a unix file descriptor to
 * listen locally for drivers that want to use it.
 */
static void sc_newconn_master(sc_newconn_t *nc, char *buf, size_t len)
{
  char resp[256], sab[128], filename[65535];
  struct sockaddr_storage sas;
  struct sockaddr_un sn;
  sc_master_t *ms = NULL;
  socklen_t sl;
  int fd;

  /*
   * these are set so that we know whether or not to take
   * responsibility for cleaning them up upon a failure condition.
   */
  fd = -1;
  filename[0] = '\0';

  sl = sizeof(sas);
  if(getpeername(nc->inet->fd.fd, (struct sockaddr *)&sas, &sl) != 0)
    {
      fprintf(stderr, "%s: could not getpeername: %s\n",
	      __func__, strerror(errno));
      goto err;
    }

  /* allocate a new master structure for the remote scamper process */
  if((ms = malloc_zero(sizeof(sc_master_t))) == NULL)
    {
      fprintf(stderr, "%s: could not alloc ms: %s\n",
	      __func__, strerror(errno));
      goto err;
    }

  /* allocate a unit to describe this */
  if((ms->unit = sc_unit_alloc(UNIT_TYPE_MASTER, ms)) == NULL)
    {
      fprintf(stderr, "%s: could not alloc unit: %s\n",
	      __func__, strerror(errno));
      goto err;
    }

  if((ms->clients = dlist_alloc()) == NULL)
    {
      fprintf(stderr, "%s: could not alloc clients: %s\n",
	      __func__, strerror(errno));
      goto err;
    }
  dlist_onremove(ms->clients, (dlist_onremove_t)sc_master_clients_onremove);

  /* create a unix domain socket for the remote scamper process */
  sockaddr_tostr((struct sockaddr *)&sas, sab, sizeof(sab));
  if((ms->name = strdup(sab)) == NULL)
    {
      fprintf(stderr, "could not strdup ms->name: %s\n", strerror(errno));
      goto err;
    }
  if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
      fprintf(stderr, "could not create unix socket: %s\n", strerror(errno));
      goto err;
    }
  snprintf(filename, sizeof(filename), "%s/%s", unix_name, sab);
  if(sockaddr_compose_un((struct sockaddr *)&sn, filename) != 0)
    {
      filename[0] = '\0'; /* could not actually bind so no unlink */
      fprintf(stderr, "could not compose socket: %s\n", strerror(errno));
      goto err;
    }
  if(bind(fd, (struct sockaddr *)&sn, sizeof(sn)) != 0)
    {
      filename[0] = '\0'; /* could not actually bind so no unlink */
      fprintf(stderr, "could not bind unix socket: %s\n", strerror(errno));
      goto err;
    }
  if(listen(fd, -1) != 0)
    {
      fprintf(stderr, "could not listen unix socket: %s\n", strerror(errno));
      goto err;
    }

  /*
   * at this point, allocate the unix_fd structure and take
   * responsibility for the socket and filesystem point
   */
  if((ms->unix_fd = sc_fd_alloc(fd, FD_TYPE_MASTER_UNIX, ms->unit)) == NULL)
    {
      fprintf(stderr, "%s: could not alloc unix fd: %s\n",
	      __func__, strerror(errno));
      goto err;
    }
  filename[0] = '\0'; fd = -1;

#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
  if(sc_fd_read_add(ms->unix_fd) != 0)
    {
      fprintf(stderr, "%s: could not monitor unix fd: %s\n",
	      __func__, strerror(errno));
      goto err;
    }
#endif

  /* shift the internet socket from the newconn to the master */
  ms->inet = nc->inet; nc->inet = NULL;
  scamper_linepoll_update(ms->inet->lp,
			  (scamper_linepoll_handler_t)sc_master_inet_lp, ms);
  ms->inet->fd.type = FD_TYPE_MASTER_INET;
  ms->inet->fd.unit = ms->unit;

  if((ms->node = dlist_tail_push(mslist, ms)) == NULL)
    {
      fprintf(stderr, "could not push to mslist: %s\n", strerror(errno));
      goto err;
    }

  snprintf(resp, sizeof(resp), "OK %s\n", sab);
  if(sc_master_inet_send(ms, resp, strlen(resp)) != 0)
    {
      fprintf(stderr, "could not write OK: %s\n", strerror(errno));
      goto err;
    }

  return;

 err:
  if(fd != -1) close(fd);
  if(filename[0] != '\0') unlink(filename);
  if(ms != NULL) sc_master_free(ms);
  return;
}

/*
 * sc_newconn_callback
 *
 * a remote scamper connection has written an entire line and has
 * supplied a callback number.  check to see if we have a matching
 * callback number.
 */
static void sc_newconn_callback(sc_newconn_t *nc, char *buf, size_t len)
{
  sc_client_t *cn = NULL;
  sc_master_t *ms = NULL;
  sc_magic_t *mg = NULL;
  int unix_fd = -1;

  if(len == 0)
    return;

  while(*buf != '\0')
    {
      if(isspace((int)*buf) == 0)
	break;
      buf++;
    }

  /* find the unix_fd locally, take a copy of it, and then let the magic go */
  if((mg = sc_magic_find(buf)) == NULL)
    return;
  ms = mg->master;
  unix_fd = mg->unix_fd; mg->unix_fd = -1;
  sc_magic_free(mg); mg = NULL;

  /* allocate a new client structure */
  if((cn = malloc_zero(sizeof(sc_client_t))) == NULL)
    {
      fprintf(stderr, "%s: could not alloc client: %s\n",
	      __func__, strerror(errno));
      goto err;
    }

  /* allocate a unit to describe this structure */
  if((cn->unit = sc_unit_alloc(UNIT_TYPE_CLIENT, cn)) == NULL)
    {
      fprintf(stderr, "%s: could not alloc unit: %s\n",
	      __func__, strerror(errno));
      goto err;
    }

  if((cn->unix_fd = sc_fd_alloc(unix_fd,FD_TYPE_CLIENT_UNIX,cn->unit)) == NULL)
    {
      fprintf(stderr, "%s: could not alloc unix_fd: %s\n",
	      __func__, strerror(errno));
      goto err;
    }
  unix_fd = -1;
  sc_fd_read_add(cn->unix_fd);

  cn->inet = nc->inet; nc->inet = NULL;
  cn->inet->fd.unit = cn->unit;
  cn->inet->fd.type = FD_TYPE_CLIENT_INET;
  scamper_linepoll_update(cn->inet->lp,
			  (scamper_linepoll_handler_t)sc_client_inet_lp, cn);

  if((cn->unix_lp = scamper_linepoll_alloc((scamper_linepoll_handler_t)
					   sc_client_unix_lp, cn)) == NULL)
    goto err;
  if((cn->unix_wb = scamper_writebuf_alloc()) == NULL)
    goto err;

  if((cn->node = dlist_tail_push(ms->clients, cn)) == NULL)
    goto err;
  cn->master = ms;

  return;

 err:
  if(cn != NULL) sc_client_free(cn);
  if(unix_fd != -1) close(unix_fd);
  return;
}

/*
 * sc_newconn_inet_lp
 *
 * a remote scamper connection has written an entire line and we are about
 * to act accordingly: either the its a new scamper instance ready to
 * call back, or it is a scamper instance that is calling back.
 */
static int sc_newconn_inet_lp(sc_newconn_t *nc, uint8_t *buf, size_t len)
{
  if(strcasecmp((char *)buf, "master") == 0)
    sc_newconn_master(nc, (char *)buf, len);
  else if(len > 8 && strncasecmp((char *)buf, "callback", 8) == 0)
    sc_newconn_callback(nc, (char *)(buf+8), len-8);
  else
    printf("%s: unexpected input\n", __func__);
  sc_unit_gc(nc->unit);
  return 0;
}

static void sc_newconn_inet_write(sc_newconn_t *nc)
{
  if(scamper_writebuf_write(nc->inet->fd.fd, nc->inet->wb) != 0)
    {
      sc_unit_gc(nc->unit);
      return;
    }

#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
  if(scamper_writebuf_len(nc->inet->wb) == 0 &&
     sc_fd_write_del(&nc->inet->fd) != 0)
    {
      sc_unit_gc(nc->unit);
      return;
    }
#endif
  return;
}

/*
 * sc_newconn_inet_read
 *
 * the remote scamper process has initiated a new connection and written
 * something.  deal with it.
 */
static void sc_newconn_inet_read(sc_newconn_t *nc)
{
  if(sc_inet_read(nc->inet) != 0)
    {
      printf("%s: sc_inet_read failed\n", __func__);
      sc_unit_gc(nc->unit);
    }
  return;
}

static void sc_newconn_free(sc_newconn_t *nc)
{
  if(nc == NULL)
    return;
  if(nc->inet != NULL) sc_inet_free(nc->inet);
  if(nc->unit != NULL) sc_unit_free(nc->unit);
  if(nc->node != NULL) dlist_node_pop(nclist, nc->node);
  free(nc);
  return;
}

/*
 * serversocket_accept
 *
 * a new connection has arrived.  accept the new connection while we wait
 * to understand the intention behind the socket.
 */
static int serversocket_accept(int ss)
{
  struct sockaddr_storage sas;
  sc_newconn_t *nc = NULL;
  socklen_t slen;
  int inet_fd = -1;

  slen = sizeof(ss);
  if((inet_fd = accept(ss, (struct sockaddr *)&sas, &slen)) == -1)
    {
      fprintf(stderr, "could not accept: %s\n", strerror(errno));
      goto err;
    }
  if(fcntl_set(inet_fd, O_NONBLOCK) == -1)
    {
      fprintf(stderr, "could not set O_NONBLOCK: %s\n", strerror(errno));
      goto err;
    }
  if(opt_keepalives == 1 && socket_tka(inet_fd) != 0)
    goto err;

  if((nc = malloc_zero(sizeof(sc_newconn_t))) == NULL)
    {
      fprintf(stderr, "%s: could not alloc nc: %s\n",
	      __func__, strerror(errno));
      goto err;
    }

  /* allocate a unit to describe this */
  if((nc->unit = sc_unit_alloc(UNIT_TYPE_NEWCONN, nc)) == NULL)
    {
      fprintf(stderr, "%s: could not alloc unit: %s\n",
	      __func__, strerror(errno));
      goto err;
    }

  if((nc->inet = sc_inet_alloc(inet_fd)) == NULL)
    goto err;
  inet_fd = -1;
  nc->inet->fd.type = FD_TYPE_NEWCONN;
  nc->inet->fd.unit = nc->unit;
  scamper_linepoll_update(nc->inet->lp,
			  (scamper_linepoll_handler_t)sc_newconn_inet_lp, nc);

#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
  if(sc_fd_read_add(&nc->inet->fd) != 0)
    {
      fprintf(stderr, "%s: could not monitor inet fd: %s\n",
	      __func__, strerror(errno));
      goto err;
    }
#endif

  gettimeofday_wrap(&nc->tv);
  nc->tv.tv_sec += 30;

  if((nc->node = dlist_tail_push(nclist, nc)) == NULL)
    {
      fprintf(stderr, "%s: could not push to nclist: %s\n",
	      __func__, strerror(errno));
      goto err;
    }

  return 0;

 err:
  if(inet_fd != -1) close(inet_fd);
  if(nc != NULL) sc_newconn_free(nc);
  return -1;
}

/*
 * serversocket_init
 *
 * create two sockets so that we can use both IPv4 and IPv6 for incoming
 * connections from remote scamper processes.
 */
static int serversocket_init(void)
{
  struct sockaddr_storage sas;
  int i, pf, opt;
  for(i=0; i<2; i++)
    {
      pf = i == 0 ? PF_INET : PF_INET6;
      if((pf == PF_INET  && (options & OPT_IPV4) == 0) ||
	 (pf == PF_INET6 && (options & OPT_IPV6) == 0))
	continue;

      if((serversockets[i] = socket(pf, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
	  fprintf(stderr, "could not open %s socket: %s\n",
		  i == 0 ? "ipv4" : "ipv6", strerror(errno));
	  return -1;
	}

      opt = 1;
      if(setsockopt(serversockets[i], SOL_SOCKET, SO_REUSEADDR,
		    (char *)&opt, sizeof(opt)) != 0)
	{
	  fprintf(stderr, "could not set SO_REUSEADDR: %s\n",
		  strerror(errno));
	  return -1;
	}

      if(opt_keepalives == 1 && socket_tka(serversockets[i]) != 0)
	return -1;

#ifdef IPV6_V6ONLY
      if(pf == PF_INET6)
	{
	  opt = 1;
	  if(setsockopt(serversockets[i], IPPROTO_IPV6, IPV6_V6ONLY,
			(char *)&opt, sizeof(opt)) != 0)
	    {
	      fprintf(stderr, "could not set IPV6_V6ONLY: %s\n",
		      strerror(errno));
	      return -1;
	    }
	}
#endif

      sockaddr_compose((struct sockaddr *)&sas, pf, NULL, port);
      if(bind(serversockets[i], (struct sockaddr *)&sas,
	      sockaddr_len((struct sockaddr *)&sas)) != 0)
	{
	  fprintf(stderr, "could not bind %s socket to port %d: %s\n",
		  i == 0 ? "ipv4" : "ipv6", port, strerror(errno));
	  return -1;
	}
      if(listen(serversockets[i], -1) != 0)
	{
	  fprintf(stderr, "could not listen %s socket: %s\n",
		  i == 0 ? "ipv4" : "ipv6", strerror(errno));
	  return -1;
	}
    }
  return 0;
}

/*
 * unixdomain_direxists
 *
 * make sure the directory specified actually exists
 */
static int unixdomain_direxists(void)
{
  struct stat sb;
  if(stat(unix_name, &sb) != 0)
    {
      usage(OPT_UNIX);
      fprintf(stderr, "could not stat %s: %s\n", unix_name, strerror(errno));
      return -1;
    }
  if((sb.st_mode & S_IFDIR) != 0)
    return 0;
  usage(OPT_UNIX);
  fprintf(stderr, "%s is not a directory\n", unix_name);
  return -1;
}

static void cleanup(void)
{
  int i;

  for(i=0; i<2; i++)
    close(serversockets[i]);

  if(mslist != NULL)
    dlist_free_cb(mslist, (dlist_free_t)sc_master_free);

#ifdef HAVE_OPENSSL
  if(tls_ctx != NULL) SSL_CTX_free(tls_ctx);
#endif

  if(nclist != NULL) dlist_free(nclist);
  if(magictree != NULL) splaytree_free(magictree, NULL);
  if(gclist != NULL) dlist_free(gclist);

#ifdef HAVE_EPOLL
  if(epfd != -1) close(epfd);
#endif

#ifdef HAVE_KQUEUE
  if(kqfd != -1) close(kqfd);
#endif

  return;
}

static void remoted_sig(int sig)
{
  if(sig == SIGHUP || sig == SIGINT)
    stop = 1;
  return;
}

#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
#if defined(HAVE_EPOLL)
static int epoll_loop(void)
#else
static int kqueue_loop(void)
#endif
{
#if defined(HAVE_EPOLL)
  struct epoll_event events[1024];
  int events_c = sizeof(events) / sizeof(struct epoll_event);
  int timeout;
#else
  struct kevent events[1024];
  int events_c = sizeof(events) / sizeof(struct kevent);
  struct timespec ts, *timeout;
#endif
  struct timeval now, tv;
  sc_newconn_t *nc;
  dlist_node_t *dn;
  sc_fd_t *scfd, scfd_ss[2];
  sc_unit_t *scu;
  int i, rc;

#if defined(HAVE_EPOLL)
  if((epfd = epoll_create(1000)) == -1)
    {
      fprintf(stderr, "%s: epoll_create failed: %s\n",
	      __func__, strerror(errno));
      return -1;
    }
#else
  if((kqfd = kqueue()) == -1)
    {
      fprintf(stderr, "%s: kqueue failed: %s\n", __func__, strerror(errno));
      return -1;
    }
#endif

  /* add the server sockets to the poll set */
  memset(&scfd_ss, 0, sizeof(scfd_ss));
  for(i=0; i<2; i++)
    {
      if(serversockets[i] == -1)
	continue;
      scfd_ss[i].type = FD_TYPE_SERVER;
      scfd_ss[i].fd = serversockets[i];
      if(sc_fd_read_add(&scfd_ss[i]) != 0)
	return -1;
    }

  /* main event loop */
  while(stop == 0)
    {
#if defined(HAVE_EPOLL)
      timeout = -1;
#else
      timeout = NULL;
#endif
      if((dn = dlist_head_node(nclist)) != NULL)
	{
	  gettimeofday_wrap(&now);
	  while(dn != NULL)
	    {
	      nc = dlist_node_item(dn);
	      dn = dlist_node_next(dn);
	      if(timeval_cmp(&now, &nc->tv) >= 0)
		{
		  sc_newconn_free(nc);
		  continue;
		}
	      timeval_diff_tv(&tv, &now, &nc->tv);
#if defined(HAVE_EPOLL)
	      timeout = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
	      if(timeout == 0 && tv.tv_usec != 0)
		timeout++;
#else
	      ts.tv_sec = tv.tv_sec;
	      ts.tv_nsec = tv.tv_usec * 1000;
	      timeout = &ts;
#endif
	      break;
	    }
	}

#if defined(HAVE_EPOLL)
      if((rc = epoll_wait(epfd, events, events_c, timeout)) == -1)
	{
	  if(errno == EINTR)
	    continue;
	  fprintf(stderr, "%s: epoll_wait failed: %s\n",
		  __func__, strerror(errno));
	  return -1;
	}
#else
      if((rc = kevent(kqfd, NULL, 0, events, events_c, timeout)) == -1)
	{
	  if(errno == EINTR)
	    continue;
	  fprintf(stderr, "%s: kqueue_event failed: %s\n",
		  __func__, strerror(errno));
	  return -1;
	}
#endif

      for(i=0; i<rc; i++)
	{
#if defined(HAVE_EPOLL)
	  scfd = events[i].data.ptr;
#else
	  scfd = events[i].udata;
#endif

	  if((scu = scfd->unit) == NULL)
	    {
	      serversocket_accept(scfd->fd);
	      continue;
	    }

#if defined(HAVE_EPOLL)
	  if(events[i].events & EPOLLIN && scu->gc == 0)
	    read_cb[scfd->type](scu->data);
	  if(events[i].events & EPOLLOUT && scu->gc == 0)
	    write_cb[scfd->type](scu->data);
#else
	  if(scu->gc != 0)
	    continue;
	  if(events[i].filter == EVFILT_READ)
	    read_cb[scfd->type](scu->data);
	  else if(events[i].filter == EVFILT_WRITE)
	    write_cb[scfd->type](scu->data);
#endif
	}

      while((scu = dlist_head_pop(gclist)) != NULL)
	unit_gc[scu->type](scu->data);
    }

  return 0;
}
#endif

static int select_loop(void)
{
  struct timeval now, tv, *timeout;
  fd_set rfds;
  fd_set wfds, *wfdsp;
  int i, count, nfds;
  dlist_node_t *dn, *dn2;
  sc_newconn_t *nc;
  sc_master_t *ms;
  sc_client_t *cn;
  sc_unit_t *scu;

  while(stop == 0)
    {
      FD_ZERO(&rfds); FD_ZERO(&wfds);
      wfdsp = NULL; nfds = -1; timeout = NULL;

      for(i=0; i<2; i++)
	{
	  if(serversockets[i] == -1)
	    continue;
	  FD_SET(serversockets[i], &rfds);
	  if(serversockets[i] > nfds)
	    nfds = serversockets[i];
	}

      if((dn = dlist_head_node(nclist)) != NULL)
	{
	  gettimeofday_wrap(&now);
	  while(dn != NULL)
	    {
	      nc = dlist_node_item(dn);
	      dn = dlist_node_next(dn);

	      if(timeout == NULL)
		{
		  if(timeval_cmp(&now, &nc->tv) >= 0)
		    {
		      sc_newconn_free(nc);
		      continue;
		    }
		  timeval_diff_tv(&tv, &now, &nc->tv);
		  timeout = &tv;
		}

	      FD_SET(nc->inet->fd.fd, &rfds);
	      if(nc->inet->fd.fd > nfds)
		nfds = nc->inet->fd.fd;
	      if(scamper_writebuf_len(nc->inet->wb) > 0)
		{
		  FD_SET(nc->inet->fd.fd, &wfds);
		  wfdsp = &wfds;
		}
	    }
	}

      dn=dlist_head_node(mslist);
      while(dn != NULL)
	{
	  ms = dlist_node_item(dn);
	  dn = dlist_node_next(dn);
	  FD_SET(ms->inet->fd.fd, &rfds);
	  if(ms->inet->fd.fd > nfds) nfds = ms->inet->fd.fd;
	  FD_SET(ms->unix_fd->fd, &rfds);
	  if(ms->unix_fd->fd > nfds) nfds = ms->unix_fd->fd;

	  if(scamper_writebuf_len(ms->inet->wb) > 0)
	    {
	      FD_SET(ms->inet->fd.fd, &wfds);
	      wfdsp = &wfds;
	    }

	  dn2 = dlist_head_node(ms->clients);
	  while(dn2 != NULL)
	    {
	      cn = dlist_node_item(dn2);
	      dn2 = dlist_node_next(dn2);
	      if(cn->inet->fd.fd != -1)
		{
		  FD_SET(cn->inet->fd.fd, &rfds);
		  if(cn->inet->fd.fd > nfds) nfds = cn->inet->fd.fd;
		  if(scamper_writebuf_len(cn->inet->wb) > 0)
		    {
		      FD_SET(cn->inet->fd.fd, &wfds);
		      wfdsp = &wfds;
		    }
		}
	      FD_SET(cn->unix_fd->fd, &rfds);
	      if(cn->unix_fd->fd > nfds) nfds = cn->unix_fd->fd;
	      if(scamper_writebuf_len(cn->unix_wb) > 0)
		{
		  FD_SET(cn->unix_fd->fd, &wfds);
		  wfdsp = &wfds;
		}
	    }
	}

      if((count = select(nfds+1, &rfds, wfdsp, NULL, NULL)) < 0)
	{
	  if(errno == EINTR)
	    continue;
	  fprintf(stderr, "select failed: %s\n", strerror(errno));
	  return -1;
	}

      if(count > 0)
	{
	  for(i=0; i<2; i++)
	    {
	      if(serversockets[i] != -1 &&
		 FD_ISSET(serversockets[i], &rfds) &&
		 serversocket_accept(serversockets[i]) != 0)
		return -1;
	    }

	  for(dn=dlist_head_node(nclist); dn != NULL; dn=dlist_node_next(dn))
	    {
	      nc = dlist_node_item(dn);
	      if(FD_ISSET(nc->inet->fd.fd, &rfds))
		sc_newconn_inet_read(nc);
	      if(nc->unit->gc == 0 && wfdsp != NULL &&
		 FD_ISSET(nc->inet->fd.fd, wfdsp))
		sc_newconn_inet_write(nc);
	    }

	  for(dn=dlist_head_node(mslist); dn != NULL; dn=dlist_node_next(dn))
	    {
	      ms = dlist_node_item(dn);
	      if(FD_ISSET(ms->inet->fd.fd, &rfds))
		sc_master_inet_read(ms);
	      if(ms->unit->gc == 0 && FD_ISSET(ms->unix_fd->fd, &rfds))
		sc_master_unix_accept(ms);
	      if(ms->unit->gc == 0 && wfdsp != NULL &&
		 FD_ISSET(ms->inet->fd.fd, wfdsp))
		sc_master_inet_write(ms);

	      for(dn2 = dlist_head_node(ms->clients);
		  dn2 != NULL && ms->unit->gc == 0;
		  dn2 = dlist_node_next(dn2))
		{
		  cn = dlist_node_item(dn2);
		  if(cn->inet->fd.fd != -1)
		    {
		      if(FD_ISSET(cn->inet->fd.fd, &rfds))
			sc_client_inet_read(cn);
		      if(wfdsp != NULL && FD_ISSET(cn->inet->fd.fd, wfdsp))
			sc_client_inet_write(cn);
		    }

		  if(FD_ISSET(cn->unix_fd->fd, &rfds))
		    sc_client_unix_read(cn);
		  if(wfdsp != NULL && FD_ISSET(cn->unix_fd->fd, wfdsp))
		    sc_client_unix_write(cn);
		}
	    }
	}

      while((scu = dlist_head_pop(gclist)) != NULL)
	unit_gc[scu->type](scu->data);
    }

  return 0;
}

int main(int argc, char *argv[])
{
  int i;

#ifndef _WIN32
  struct sigaction si_sa;
#endif

#ifdef DMALLOC
  free(malloc(1));
#endif

  for(i=0; i<2; i++)
    serversockets[i] = -1;

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    return -1;

#ifdef HAVE_OPENSSL
  if(tls_certfile != NULL)
    {
      SSL_library_init();
      SSL_load_error_strings();
      if((tls_ctx = SSL_CTX_new(SSLv23_method())) == NULL)
	return -1;
      if(SSL_CTX_use_certificate_file(tls_ctx,tls_certfile,SSL_FILETYPE_PEM)!=1)
	{
	  printf("could not SSL_CTX_use_certificate_file\n");
	  ERR_print_errors_fp(stderr);
	  return -1;
	}
      if(SSL_CTX_use_PrivateKey_file(tls_ctx,tls_privfile,SSL_FILETYPE_PEM)!=1)
	{
	  printf("could not SSL_CTX_use_PrivateKey_file\n");
	  ERR_print_errors_fp(stderr);
	  return -1;
	}
      SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_NONE, NULL);
      SSL_CTX_set_options(tls_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    }
#endif

#ifdef HAVE_DAEMON
  if((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
    return -1;
#endif

#ifndef _WIN32
  sigemptyset(&si_sa.sa_mask);
  si_sa.sa_flags   = 0;
  si_sa.sa_handler = remoted_sig;
  if(sigaction(SIGHUP, &si_sa, 0) == -1)
    {
      fprintf(stderr, "could not set sigaction for SIGHUP");
      return -1;
    }
  if(sigaction(SIGINT, &si_sa, 0) == -1)
    {
      fprintf(stderr, "could not set sigaction for SIGINT");
      return -1;
    }
#endif

  if(unixdomain_direxists() != 0 || serversocket_init() != 0)
    return -1;

  if((mslist = dlist_alloc()) == NULL ||
     (nclist = dlist_alloc()) == NULL ||
     (gclist = dlist_alloc()) == NULL ||
     (magictree = splaytree_alloc((splaytree_cmp_t)sc_magic_cmp)) == NULL)
    return -1;
  dlist_onremove(mslist, (dlist_onremove_t)sc_master_onremove);
  dlist_onremove(gclist, (dlist_onremove_t)sc_unit_onremove);

#if defined(HAVE_EPOLL)
  if(opt_select == 0)
    return epoll_loop();
#elif defined(HAVE_KQUEUE)
  if(opt_select == 0)
    return kqueue_loop();
#endif

  return select_loop();
}
