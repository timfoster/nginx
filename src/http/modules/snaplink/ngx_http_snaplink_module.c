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
 * 1. Determine the source from the SOURCE_HEADER_NAME header
 * 2. Ensure the target directory exists
 * 3. link() the target
 * 4. Return success or error
 *
 *
 * References:
 *
 *  - http://mailman.nginx.org/pipermail/nginx/2007-August/001559.html
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_thread_pool.h>
#include <ngx_md5.h>

#include <atomic.h>
#include <libgen.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/stat.h>
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

#define SOURCE_HEADER_NAME "Snaplink-Source"

typedef struct {
    ngx_flag_t      snap_enabled;
    ngx_str_t       snap_root;
} snaplink_loc_conf_t;

/* Forwards */
ngx_module_t ngx_http_snaplink_module;

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
 *
 */
static ngx_int_t
snaplink_handler(ngx_http_request_t *r)
{
    snaplink_loc_conf_t *conf;
    ngx_list_t list;
    ngx_list_part_t *part;
    ngx_table_elt_t *data;
    ngx_uint_t i;
    char *errstr;
    char *last_slash;
    int saved_errno;
    char source[PATH_MAX];
    char target[PATH_MAX];
    char target_dir[PATH_MAX];

    conf = ngx_http_get_module_loc_conf(r, ngx_http_snaplink_module);
    if (conf->snap_enabled != 1) {
        // This is not a request for us!
        return (NGX_DECLINED);
    }

    if (r->method != NGX_HTTP_PUT) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "Only \"PUT\" requests allowed");
        return (NGX_HTTP_NOT_ALLOWED);
    }

    /*
     * NOTE:
     *
     * nginx has an faster hashed version of header lookup, but does not make it
     * clear how to get your headers hashed so we don't currently use that. See:
     *
     * https://www.nginx.com/resources/wiki/start/topics/examples/headers_management/#quick-search-with-hash
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

        if (strncasecmp((const char *)data[i].key.data, SOURCE_HEADER_NAME, sizeof(SOURCE_HEADER_NAME) - 1) == 0) {
            // XXX check results
            strcpy(source, "/manta/");
            strncat(source, (const char *)data[i].value.data, data[i].value.len);
            strcpy(target, "/manta/");
            strncat(target, (const char *)r->uri.data + strlen("/snaplink/v1/"), r->uri.len - strlen("/snaplink/v1/"));
            strcpy(target_dir, target);

            // TODO: validate all these strings look how we expect.

            last_slash = strrchr(target_dir, '/');
            if (last_slash == NULL) {
                // XXX What errors should we handle?
                break;
            }
            last_slash[0] = '\0';

            errno = 0;
            if ((mkdir(target_dir, 0755) != 0) && (errno != EEXIST)) {

                // strerror might change errno, so we save the original
                saved_errno = errno;
                errstr = strerror(errno);

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to create target_dir[%s]: '%s' %d", target_dir, errstr, saved_errno);
                return (NGX_HTTP_INTERNAL_SERVER_ERROR);
            } else {
                // TODO: NGX_LOG_DEBUG?
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "created target_dir[%s]", target_dir);
            }

            errno = 0;
            if (link(source, target) != 0) {
                if (errno == ENOENT) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "source[%s] does not exist, cannot create link target[%s]", source, target);
                    return (NGX_HTTP_NOT_FOUND);
                }

                // strerror might change errno, so we save the original
                saved_errno = errno;
                errstr = strerror(errno);

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to link source[%s] to target[%s]: '%s' (%d)", source, target, errstr, saved_errno);
                return (NGX_HTTP_INTERNAL_SERVER_ERROR);
            } else {
                // TODO: NGX_LOG_DEBUG?
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "linked source[%s] to target[%s]", source, target);
                return (NGX_HTTP_NO_CONTENT);
            }
        }
    }

    return (NGX_HTTP_BAD_REQUEST);
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
    NULL,                     /* preconfiguration */
    snaplink_init,            /* postconfiguration */

    NULL,                     /* create main configuration */
    NULL,                     /* init main configuration */

    NULL,                     /* create server configuration */
    NULL,                     /* merge server configuration */

    snaplink_create_loc_conf, /* create location configuration */
    snaplink_merge_loc_conf   /* merge location configuration */

};

ngx_module_t ngx_http_snaplink_module = {
    NGX_MODULE_V1,
    &ngx_http_snaplink_module_ctx,  /* module context */
    snaplink_commands,              /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    NULL,                           /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};
