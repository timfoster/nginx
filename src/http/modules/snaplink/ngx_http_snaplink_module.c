/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.*
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Module to hard-link files for Manta's SnapLink features (see RFD 171).
 *
 * This is implemented as an nginx module, which is currently compiled into
 * nginx. It is based on the MPU module. As part of nginx, there are two main
 * things that we define:
 *
 * 1. A function which initializes and inserts us into the request handling
 *    array (snaplink_init()).
 *
 * 2. Functions to manipulate the configuration options and a table of options
 *    (snaplink_create_loc_conf() and snaplink_merge_loc_conf()).
 *
 * nginx's configuration is logically broken down into different name spaces
 * based on what it influences. The snaplink module focuses on the 'location'
 * level, which corresponds to the 'location' keyword, which is meant to refer
 * to a section of the server's HTTP name space. When nginx is started up, it
 * invokes our two configuration functions for different portions of the
 * configuration tree. A user is required to set 'snaplink_enabled', for a given
 * section to be relevant for snaplinks. All URLs under a given location will be
 * used for snaplink processing.
 *
 * As part of the snaplink_init() function, this module inserts its own function
 * into the request processing pipeline. This function, snaplink_handler(), is
 * called for most HTTP requests. If this function returns NGX_DECLINED, then we
 * move onto the next phase of the pipeline. Otherwise, if we return that we're
 * handling this request, nginx will wait for us to finish the request. Finally,
 * if we return an error, then nginx will return an error to the client
 * immediately.
 *
 * If the 'snaplink_enabled' flag is not set for the given location which the
 * URI maps to, then we'll always return NGX_DECLINED, so that it is handled by
 * another part of the system. This is how the dav module or the basic HTTP get
 * part works.
 *
 * If 'snaplink_enabled' has been set to on, then we proceed to process the
 * request as a snaplink. This happens in a few high-level steps:
 *
 * 1. Determine the source from the XXX header
 * 2. Ensure the target directory exists
 * 3. link() the target
 * 4. Return success or error
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_thread_pool.h>
#include <ngx_md5.h>
#include <strings.h>
#include <libgen.h>
#include <stdarg.h>
#include <sys/debug.h>
#include <atomic.h>
#include <unistd.h>


/*
 * Be paranoid about making sure we have 64-bit interfaces.
 */
#if defined(__i386) && !defined(_FILE_OFFSET_BITS)
#error "32-bit build without _FILE_OFFSET_BITS"
#endif

#if defined(__i386) && _FILE_OFFSET_BITS != 64
#error "incorrect value for _FILE_OFFSET_BITS"
#endif

typedef struct {
    ngx_flag_t      snap_enabled;
    ngx_str_t       snap_root;
} snaplink_loc_conf_t;

/*
 * This is a per-request structure that is allocated as part of the thread pool
 * task allocation.
 */
typedef struct {
    ngx_http_request_t  *snapr_http;
    ngx_thread_task_t   *snapr_task;
    char            *snapr_buf;
    size_t          snapr_buflen;
    const char      *snapr_account;
    const char      *snapr_objid;
    const char      *snapr_root;
    const char      *snapr_req_md5;
    int64_t         snapr_nbytes;
    ngx_int_t       snapr_status;
    ngx_buf_t       snapr_ngx_buf;
} snaplink_request_t;

/* Forwards */
ngx_module_t ngx_http_snaplink_module;

/*
 * Stat to keep track of times we can't schedule data on a thread pool.
 */
volatile uint64_t snaplink_overloads;

/*
 * Basically we want a way to indicate in a few functions that the target file
 * already exists. Hence the SNAPLINK_EALREADY.
 */
typedef enum {
    SNAPLINK_FAILURE = -1,
    SNAPLINK_SUCCESS = 0,
    SNAPLINK_EALREADY = 1
} snaplink_status_t;

static ngx_command_t  snaplink_commands[] = {
    { ngx_string("snaplink_enabled"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(snaplink_loc_conf_t, snap_enabled),
        NULL },

    { ngx_string("snaplink_root"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(snaplink_loc_conf_t, snap_root),
        NULL },

    ngx_null_command
};

static void *
snaplink_create_loc_conf(ngx_conf_t *cf)
{
    snaplink_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof (snaplink_loc_conf_t));
    if (conf == NULL) {
        return (NULL);
    }

    conf->snap_enabled = NGX_CONF_UNSET;
    conf->snap_root.len = 0;
    conf->snap_root.data = NULL;

    return (conf);
}

static char *
snaplink_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    snaplink_loc_conf_t *prev = parent;
    snaplink_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->snap_enabled, prev->snap_enabled, 0);
    ngx_conf_merge_str_value(conf->snap_root, prev->snap_root, "");

    if (conf->snap_enabled == 1 && (conf->snap_root.len == 0 ||
        (conf->snap_root.len == 0 && conf->snap_root.data[0] == '\0'))) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "missing required snaplink setting \"snaplink_root\"");
        return (NGX_CONF_ERROR);
    }

    return (NGX_CONF_OK);
}

/*
 * This is the primary function that is called by nginx to handle a request.
 */
static ngx_int_t
snaplink_handler(ngx_http_request_t *r)
{
    snaplink_loc_conf_t *conf;
    ngx_list_t list;
    ngx_list_part_t *part;
    char **data;
    unsigned int i;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_snaplink_module);
    if (conf->snap_enabled != 1) {
        return (NGX_DECLINED);
    }

    if (r->method != NGX_HTTP_PUT) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "Only \"PUT\" requests allowed");
        return (NGX_HTTP_NOT_ALLOWED);
    }

/*
        int link(const char *existing, const char *new);
 */

    list = r->headers_in.headers;
    part = &list.part;
    data = part->elts;

    for (i = 0 ;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            data = part->elts;
            i = 0;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, data[i]);
    }
    r->request_body_file_log_level = 0;

    return (NGX_HTTP_NOT_ALLOWED);
}

static ngx_int_t
snaplink_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return (NGX_ERROR);
    }

    *h = snaplink_handler;

    return (NGX_OK);
}

static ngx_http_module_t ngx_http_snaplink_module_ctx = {
    NULL,           /* preconfiguration */
    snaplink_init,      /* postconfiguration */

    NULL,           /* create main configuration */
    NULL,           /* init main configuration */

    NULL,           /* create server configuration */
    NULL,           /* merge server configuration */

    snaplink_create_loc_conf,   /* create location configuration */
    snaplink_merge_loc_conf /* merge location configuration */

};

ngx_module_t ngx_http_snaplink_module = {
    NGX_MODULE_V1,
    &ngx_http_snaplink_module_ctx,  /* module context */
    snaplink_commands,            /* module directives */
    NGX_HTTP_MODULE,          /* module type */
    NULL,                 /* init master */
    NULL,                 /* init module */
    NULL,                 /* init process */
    NULL,                 /* init thread */
    NULL,                 /* exit thread */
    NULL,                 /* exit process */
    NULL,                 /* exit master */
    NGX_MODULE_V1_PADDING
};
