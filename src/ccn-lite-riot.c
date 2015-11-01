/*
 * @f ccn-lite-riot.c
 * @b RIOT adaption layer
 *
 * Copyright (C) 2011-14, Christian Tschudin, University of Basel
 * Copyright (C) 2015, Oliver Hahm, INRIA
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * File history:
 * 2015-10-26 created (based on ccn-lite-minimalrelay.c)
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include <arpa/inet.h>
#include <netinet/in.h>


/* RIOT specific includes */
#include "log.h"
#include "kernel_types.h"
#include "net/gnrc/netreg.h"
#include "ccn-lite-riot.h"

#include "ccnl-os-time.c"
// ----------------------------------------------------------------------
// "replacement lib"

#define FATAL   LOG_ERROR
#define ERROR   LOG_ERROR
#define WARNING LOG_WARNING
#define INFO    LOG_INFO
#define DEBUG   LOG_DEBUG
#define TRACE   LOG_DEBUG
#define VERBOSE LOG_ALL

#define DEBUGMSG(LVL, ...) do {       \
        if ((LVL)>debug_level) break;   \
        LOG(LVL, __VA_ARGS__);   \
    } while (0)
# define DEBUGMSG_CORE(...) DEBUGMSG(__VA_ARGS__)
# define DEBUGMSG_CFWD(...) DEBUGMSG(__VA_ARGS__)
# define DEBUGMSG_CUTL(...) DEBUGMSG(__VA_ARGS__)
# define DEBUGMSG_PIOT(...) DEBUGMSG(__VA_ARGS__)

#define DEBUGSTMT(LVL, ...) do { \
        if ((LVL)>debug_level) break; \
        __VA_ARGS__; \
     } while (0)

#define TRACEIN(...)                    do {} while(0)
#define TRACEOUT(...)                   do {} while(0)

#define CONSTSTR(s)                     s

#define free_2ptr_list(a,b)     ccnl_free(a), ccnl_free(b)
#define free_3ptr_list(a,b,c)   ccnl_free(a), ccnl_free(b), ccnl_free(c)
#define free_4ptr_list(a,b,c,d) ccnl_free(a), ccnl_free(b), ccnl_free(c), ccnl_free(d);

#define free_prefix(p)  do{ if(p) \
                free_4ptr_list(p->bytes,p->comp,p->complen,p); } while(0)
#define free_content(c) do{ /* free_prefix(c->name); */ free_packet(c->pkt); \
                        ccnl_free(c); } while(0)

#define ccnl_frag_new(a,b)                      NULL
#define ccnl_frag_destroy(e)                    do {} while(0)

#define ccnl_sched_destroy(s)           do {} while(0)

#define ccnl_mgmt(r,b,p,f)              -1

#define ccnl_nfn_monitor(a,b,c,d,e)     do{}while(0)

/* TODO: pass received content to upper layer (application */
#define ccnl_app_RX(x,y)                do{}while(0)

#define ccnl_close_socket(s)            close(s)

#define compute_ccnx_digest(b) NULL
#define local_producer(...)             0

//----------------------------------------------------------------------

#include "ccnl-defs.h"
#include "ccnl-core.h"

void free_packet(struct ccnl_pkt_s *pkt);

struct ccnl_interest_s* ccnl_interest_remove(struct ccnl_relay_s *ccnl,
                     struct ccnl_interest_s *i);
int ccnl_pkt2suite(unsigned char *data, int len, int *skip);

char* ccnl_prefix_to_path_detailed(struct ccnl_prefix_s *pr,
                    int ccntlv_skip, int escape_components, int call_slash);
#define ccnl_prefix_to_path(P) ccnl_prefix_to_path_detailed(P, 1, 0, 0)

char* ccnl_addr2ascii(sockunion *su);
void ccnl_core_addToCleanup(struct ccnl_buf_s *buf);
const char* ccnl_suite2str(int suite);
bool ccnl_isSuite(int suite);

//----------------------------------------------------------------------

struct ccnl_buf_s*
ccnl_buf_new(void *data, int len)
{
    struct ccnl_buf_s *b = ccnl_malloc(sizeof(*b) + len);

    if (!b)
        return NULL;
    b->next = NULL;
    b->datalen = len;
    if (data)
        memcpy(b->data, data, len);
    return b;
}

// ----------------------------------------------------------------------
struct ccnl_relay_s theRelay;
int debug_level;
void
ccnl_ll_TX(struct ccnl_relay_s *ccnl, struct ccnl_if_s *ifc,
           sockunion *dest, struct ccnl_buf_s *buf);

#include "ccnl-core.c"

// ----------------------------------------------------------------------
int
ccnl_open_netif(kernel_pid_t if_pid, gnrc_nettype_t netreg_type)
{
    gnrc_netreg_entry_t ne;
    ne.demux_ctx =  GNRC_NETREG_DEMUX_CTX_ALL;
    ne.pid = if_pid;
    return gnrc_netreg_register(netreg_type, &ne);
}
int
ccnl_open_udpdev(int port)
{
    int s;
    struct sockaddr_in6 si;

    s = socket(AF_INET6, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("udp socket");
        return -1;
    }

    si.sin6_addr = in6addr_any;
    si.sin6_port = htons(port);
    si.sin6_family = AF_INET6;
    if (bind(s, (struct sockaddr *)&si, sizeof(si)) < 0) {
        perror("udp sock bind");
        return -1;
    }

    return s;
}

void
ccnl_ll_TX(struct ccnl_relay_s *ccnl, struct ccnl_if_s *ifc,
           sockunion *dest, struct ccnl_buf_s *buf)
{
    (void) ccnl;
    int rc;
    DEBUGMSG(TRACE, "ccnl_ll_TX %d bytes\n", buf ? buf->datalen : -1);
    switch(dest->sa.sa_family) {
#ifdef USE_IPV6
    case AF_INET6:
        rc = sendto(ifc->sock, buf->data, buf->datalen, 0, (struct sockaddr*)
                &(dest)->ip6, sizeof(struct sockaddr_in6));
        char str[INET6_ADDRSTRLEN];
        DEBUGMSG(DEBUG, "udp sendto %s/%d returned %d\n",
                 inet_ntop(AF_INET6, dest->ip6.sin6_addr.s6_addr, str,
                     INET6_ADDRSTRLEN), ntohs(dest->ip6.sin6_port), rc);
        break;
#endif
    case AF_PACKET:
        /* TODO: implement gnrc netapi call here */
        break;
    default:
        DEBUGMSG(WARNING, "unknown transport\n");
        break;
    }
    (void) rc; // just to silence a compiler warning (if USE_DEBUG is not set)
}


void ccnl_minimalrelay_ageing(void *relay, void *aux)
{
    ccnl_do_ageing(relay, aux);
    ccnl_set_timer(SEC_IN_USEC, ccnl_minimalrelay_ageing, relay, 0);
}

void
ccnl_event_loop(struct ccnl_relay_s *ccnl)
{
    int i, maxfd = -1;
    fd_set readfs, writefs;

    if (ccnl->ifcount == 0) {
        fprintf(stderr, "no socket to work with, not good, quitting\n");
        exit(EXIT_FAILURE);
    }
    for (i = 0; i < ccnl->ifcount; i++)
        if (ccnl->ifs[i].sock > maxfd)
            maxfd = ccnl->ifs[i].sock;
    maxfd++;

    FD_ZERO(&readfs);
    FD_ZERO(&writefs);
    while(!ccnl->halt_flag) {
        long timeout;

        for (i = 0; i < ccnl->ifcount; i++) {
            FD_SET(ccnl->ifs[i].sock, &readfs);
            if (ccnl->ifs[i].qlen > 0)
                FD_SET(ccnl->ifs[i].sock, &writefs);
            else
                FD_CLR(ccnl->ifs[i].sock, &writefs);
        }

        timeout = ccnl_run_events();
        (void) timeout;
        /*
        rc = select(maxfd, &readfs, &writefs, NULL, timeout);
        if (rc < 0) {
            perror("select(): ");
            exit(EXIT_FAILURE);
        }
*/
        for (i = 0; i < ccnl->ifcount; i++) {
            if (FD_ISSET(ccnl->ifs[i].sock, &readfs)) {
                sockunion src_addr;
                socklen_t addrlen = sizeof(sockunion);
                unsigned char buf[CCNL_MAX_PACKET_SIZE];
                int len;
                if ((len = recvfrom(ccnl->ifs[i].sock, buf, sizeof(buf), 0,
                                (struct sockaddr*) &src_addr, &addrlen)) > 0)
                    ccnl_core_RX(ccnl, i, buf, len, &src_addr.sa, sizeof(src_addr.ip6));
            }
            if (FD_ISSET(ccnl->ifs[i].sock, &writefs))
                ccnl_interface_CTS(&theRelay, &theRelay.ifs[0]);
        }
    }
}

