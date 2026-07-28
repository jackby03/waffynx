/*
 * ngx_http_waffynx_module.c
 *
 * Waffynx nginx module -- intercepts requests at ACCESS phase,
 * sends metadata to the Go sidecar via Unix socket, and enforces
 * the WAF verdict (allow/deny).
 *
 * nginx.conf usage:
 *
 *   location / {
 *       waffynx on;
 *       waffynx_socket /var/run/waffynx.sock;
 *       waffynx_fail_open on;
 *       proxy_pass http://backend;
 *   }
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

/* Forward declaration -- needed because access_handler references it
 * before the ngx_module_t definition at the bottom of this file. */
extern ngx_module_t ngx_http_waffynx_module;

#define WAFFYNX_MAX_BODY 65536  /* 64KB max body forwarded to sidecar */

/* ------------------------------------------------------------------ */
/*  Configuration struct                                               */
/* ------------------------------------------------------------------ */
typedef struct {
    ngx_flag_t  enabled;
    ngx_str_t   socket_path;
    ngx_msec_t  timeout;
    ngx_flag_t  fail_open;    /* 1 = allow request if sidecar is down */
    size_t      max_body_size;
} ngx_http_waffynx_loc_conf_t;

/* ------------------------------------------------------------------ */
/*  Per-request context (allocated from r->pool)                       */
/* ------------------------------------------------------------------ */
typedef struct {
    ngx_http_waffynx_loc_conf_t  *wlcf;
    u_char                       *request_buf;
    size_t                        header_len;
    ngx_uint_t                    evaluated;  /* 1 = already done */
} ngx_http_waffynx_ctx_t;

/* ------------------------------------------------------------------ */
/*  Connect to the Go sidecar's Unix socket                            */
/* ------------------------------------------------------------------ */
static ngx_int_t
ngx_http_waffynx_connect(ngx_str_t *path, ngx_msec_t timeout)
{
    int                fd;
    struct sockaddr_un sa;
    struct timeval     tv;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        return -1;
    }

    /* Set send/receive timeout */
    tv.tv_sec  = (long)(timeout / 1000);
    tv.tv_usec = (long)((timeout % 1000) * 1000);
    (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ngx_memzero(&sa, sizeof(sa));
    sa.sun_family = AF_UNIX;

    if (path->len >= sizeof(sa.sun_path)) {
        (void) close(fd);
        return -1;
    }
    ngx_memcpy(sa.sun_path, path->data, path->len);

    if (connect(fd, (struct sockaddr *) &sa, sizeof(sa)) == -1) {
        (void) close(fd);
        return -1;
    }

    return fd;
}

/* ------------------------------------------------------------------ */
/*  Build the HTTP headers that we send to the Go sidecar              */
/* ------------------------------------------------------------------ */
static ssize_t
ngx_http_waffynx_build_headers(ngx_http_request_t *r, u_char *buf, size_t size)
{
    u_char  *p = buf;
    u_char  *end = buf + size;

    /* Request line */
    p = ngx_snprintf(p, end - p,
        "GET /evaluate HTTP/1.0\r\n"
        "Host: waffynx.internal\r\n"
        "Connection: close\r\n");

    /* Original method */
    p = ngx_snprintf(p, end - p,
        "X-WN-M: %V\r\n", &r->method_name);

    /* URI + query string */
    p = ngx_snprintf(p, end - p,
        "X-WN-U: %V", &r->uri);
    if (r->args.len > 0) {
        p = ngx_snprintf(p, end - p, "?%V", &r->args);
    }
    p = ngx_snprintf(p, end - p, "\r\n");

    /* Host */
    if (r->headers_in.host) {
        p = ngx_snprintf(p, end - p,
            "X-WN-H: %V\r\n", &r->headers_in.host->value);
    }

    /* Client IP */
    if (r->connection->addr_text.len > 0) {
        p = ngx_snprintf(p, end - p,
            "X-WN-IP: %V\r\n", &r->connection->addr_text);
    }

    /* User-Agent */
    if (r->headers_in.user_agent) {
        p = ngx_snprintf(p, end - p,
            "X-WN-UA: %V\r\n", &r->headers_in.user_agent->value);
    }

    /* Content-Type */
    if (r->headers_in.content_type) {
        p = ngx_snprintf(p, end - p,
            "X-WN-CT: %V\r\n", &r->headers_in.content_type->value);
    }

    /* Referer */
    if (r->headers_in.referer) {
        p = ngx_snprintf(p, end - p,
            "X-WN-Ref: %V\r\n", &r->headers_in.referer->value);
    }

    /* Content-Length */
    if (r->headers_in.content_length_n > 0) {
        p = ngx_snprintf(p, end - p,
            "X-WN-CL: %O\r\n", r->headers_in.content_length_n);
    }

    /* Empty line = end of headers */
    p = ngx_snprintf(p, end - p, "\r\n");

    if (p >= end) {
        return -1;
    }
    return p - buf;
}

/* ------------------------------------------------------------------ */
/*  Parse the sidecar response: extract HTTP status code               */
/* ------------------------------------------------------------------ */
static ngx_int_t
ngx_http_waffynx_parse_status(u_char *data, ssize_t len, ngx_uint_t *status)
{
    u_char  *p, *end;
    ngx_uint_t code;

    if (len < 12) {
        return NGX_ERROR; /* "HTTP/1.x NNN" is at least 12 bytes */
    }

    /*
     * Response looks like: "HTTP/1.0 204 No Content\r\n..."
     * We need the 3-digit code starting at byte 9.
     */

    p   = data;
    end = data + len;

    /* Skip "HTTP/1.x " */
    if (p + 9 >= end) {
        return NGX_ERROR;
    }
    p += 9;

    /* Parse 3-digit status code */
    if (p + 3 > end) {
        return NGX_ERROR;
    }
    if (p[0] < '0' || p[0] > '9'
        || p[1] < '0' || p[1] > '9'
        || p[2] < '0' || p[2] > '9') {
        return NGX_ERROR;
    }
    code = (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');

    *status = code;
    return NGX_OK;
}

/* ------------------------------------------------------------------ */
/*  Send request to sidecar, read response, return verdict             */
/* ------------------------------------------------------------------ */
static ngx_int_t
ngx_http_waffynx_send_and_enforce(ngx_http_request_t *r,
    ngx_http_waffynx_loc_conf_t *wlcf,
    u_char *request_buf, ssize_t req_len)
{
    u_char       response_buf[8192];
    ssize_t      resp_len;
    ngx_int_t    fd;
    ngx_uint_t   status;

    fd = ngx_http_waffynx_connect(&wlcf->socket_path, wlcf->timeout);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waffynx: cannot connect to sidecar at %V (errno=%d)",
                      &wlcf->socket_path, errno);
        return wlcf->fail_open ? NGX_OK : NGX_HTTP_FORBIDDEN;
    }

    /* Send */
    if (send(fd, request_buf, (size_t) req_len, 0) != req_len) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waffynx: send() failed (errno=%d)", errno);
        (void) close(fd);
        return wlcf->fail_open ? NGX_OK : NGX_HTTP_FORBIDDEN;
    }

    /* Signal EOF so sidecar knows we are done sending */
    (void) shutdown(fd, SHUT_WR);

    /* Read the response (loop to handle TCP fragmentation) */
    resp_len = 0;
    while (resp_len < (ssize_t)(sizeof(response_buf) - 1)) {
        ssize_t n = recv(fd, response_buf + resp_len,
                         sizeof(response_buf) - 1 - resp_len, 0);
        if (n == 0) {
            break; /* EOF */
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            resp_len = -1;
            break;
        }
        resp_len += n;
        if (resp_len >= 12) {
            break; /* enough to parse status line */
        }
    }
    (void) close(fd);

    if (resp_len <= 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waffynx: recv() failed (errno=%d)", errno);
        return wlcf->fail_open ? NGX_OK : NGX_HTTP_FORBIDDEN;
    }
    response_buf[resp_len] = '\0';

    /* Parse the HTTP status code */
    if (ngx_http_waffynx_parse_status(response_buf, resp_len,
                                       &status) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waffynx: could not parse sidecar response");
        return wlcf->fail_open ? NGX_OK : NGX_HTTP_FORBIDDEN;
    }

    /* Enforce verdict */
    if (status == 204) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "waffynx: allowed request to %V", &r->uri);
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "waffynx: blocked request to %V (status=%ui)",
                  &r->uri, status);
    return NGX_HTTP_FORBIDDEN;
}

/* ------------------------------------------------------------------ */
/*  Send + enforce from a body handler callback (must finalize)        */
/* ------------------------------------------------------------------ */
static void
ngx_http_waffynx_send_and_finalize(ngx_http_request_t *r,
    ngx_http_waffynx_loc_conf_t *wlcf,
    u_char *request_buf, ssize_t req_len)
{
    ngx_int_t  rc;

    rc = ngx_http_waffynx_send_and_enforce(r, wlcf, request_buf, req_len);

    if (rc == NGX_OK) {
        r->phase_handler++;
        ngx_http_core_run_phases(r);
    } else {
        ngx_http_finalize_request(r, rc);
    }
}

/* ------------------------------------------------------------------ */
/*  Body handler callback -- called when request body is ready         */
/* ------------------------------------------------------------------ */
static void
ngx_http_waffynx_body_handler(ngx_http_request_t *r)
{
    ngx_http_waffynx_ctx_t  *ctx;
    ngx_buf_t               *body_buf;
    u_char                  *buf;
    u_char                   cl_header[64];
    ssize_t                  total;
    size_t                   body_len, copy_len, insert_len;

    ctx = ngx_http_get_module_ctx(r, ngx_http_waffynx_module);
    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    buf = ctx->request_buf;
    total = (ssize_t) ctx->header_len;

    /* Append body if available */
	if (r->request_body != NULL && r->request_body->bufs != NULL) {
		body_buf = r->request_body->bufs->buf;

        if (body_buf != NULL && body_buf->last > body_buf->pos) {
            body_len = body_buf->last - body_buf->pos;
            copy_len = body_len;
            if (copy_len > ctx->wlcf->max_body_size) {
                copy_len = ctx->wlcf->max_body_size;
            }

            /*
             * Insert Content-Length: NNN\r\n before the final \r\n
             * (the HTTP header terminator at buf + header_len - 2).
             * Then append body bytes after the terminator.
             */
            insert_len = ngx_snprintf(cl_header, sizeof(cl_header),
                                      "Content-Length: %uz\r\n", copy_len)
                         - cl_header;

            /* Shift the final \r\n forward to make room */
            ngx_memmove(buf + ctx->header_len - 2 + insert_len,
                        buf + ctx->header_len - 2, 2);

            /* Write Content-Length header */
            ngx_memcpy(buf + ctx->header_len - 2, cl_header, insert_len);

            /* Append body bytes after the shifted \r\n */
            ngx_memcpy(buf + ctx->header_len + insert_len,
                       body_buf->pos, copy_len);

            total = (ssize_t)(ctx->header_len + insert_len + copy_len);
        }
    }

    ctx->evaluated = 1;
    ngx_http_waffynx_send_and_finalize(r, ctx->wlcf, buf, total);
}

/* ------------------------------------------------------------------ */
/*  ACCESS phase handler -- called for every request                   */
/* ------------------------------------------------------------------ */
static ngx_int_t
ngx_http_waffynx_access_handler(ngx_http_request_t *r)
{
    ngx_http_waffynx_loc_conf_t  *wlcf;
    ngx_http_waffynx_ctx_t       *ctx;
    u_char                       *buf;
    ssize_t                       header_len;
    size_t                        buf_size;
    ngx_int_t                     rc;

    /* ---- 1. Get our module config for this location ---- */
    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waffynx_module);
    if (wlcf == NULL || !wlcf->enabled) {
        return NGX_DECLINED; /* module disabled, pass through */
    }

    /* Already evaluated via body handler callback — skip re-processing */
    ctx = ngx_http_get_module_ctx(r, ngx_http_waffynx_module);
    if (ctx != NULL && ctx->evaluated) {
        return NGX_DECLINED;
    }

    /* ---- 2. Build the HTTP headers ---- */
    buf_size = 8192 + wlcf->max_body_size;
    buf = ngx_pcalloc(r->pool, buf_size);
    if (buf == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waffynx: failed to allocate request buffer");
        return wlcf->fail_open ? NGX_OK : NGX_HTTP_FORBIDDEN;
    }

    header_len = ngx_http_waffynx_build_headers(r, buf, buf_size);
    if (header_len < 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waffynx: request buffer overflow");
        return wlcf->fail_open ? NGX_OK : NGX_HTTP_FORBIDDEN;
    }

    /* ---- 3. Read body if present, then evaluate ---- */
    if (r->headers_in.content_length_n > 0) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waffynx_ctx_t));
        if (ctx == NULL) {
            return wlcf->fail_open ? NGX_OK : NGX_HTTP_FORBIDDEN;
        }
        ctx->wlcf        = wlcf;
        ctx->request_buf = buf;
        ctx->header_len  = (size_t) header_len;

        ngx_http_set_ctx(r, ctx, ngx_http_waffynx_module);

        rc = ngx_http_read_client_request_body(r,
                    ngx_http_waffynx_body_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "waffynx: failed to read request body");
            return wlcf->fail_open ? NGX_OK : NGX_HTTP_FORBIDDEN;
        }
        return NGX_DONE;
    }

    /* No body: send immediately */
    return ngx_http_waffynx_send_and_enforce(r, wlcf, buf, header_len);
}

/* ------------------------------------------------------------------ */
/*  Post-configuration init: register the access phase handler         */
/* ------------------------------------------------------------------ */
static ngx_int_t
ngx_http_waffynx_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_waffynx_access_handler;

    return NGX_OK;
}

/* ------------------------------------------------------------------ */
/*  Location config: create (set defaults)                             */
/* ------------------------------------------------------------------ */
static void *
ngx_http_waffynx_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_waffynx_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waffynx_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->fail_open = NGX_CONF_UNSET;
    conf->max_body_size = NGX_CONF_UNSET_SIZE;

    return conf;
}

/* ------------------------------------------------------------------ */
/*  Location config: merge (parent -> child)                           */
/* ------------------------------------------------------------------ */
static char *
ngx_http_waffynx_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_waffynx_loc_conf_t *prev = parent;
    ngx_http_waffynx_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled,   prev->enabled,   0);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 100);
    ngx_conf_merge_value(conf->fail_open, prev->fail_open, 1);
    ngx_conf_merge_size_value(conf->max_body_size, prev->max_body_size,
                               WAFFYNX_MAX_BODY);

    if (conf->socket_path.len == 0) {
        if (prev->socket_path.len > 0) {
            conf->socket_path = prev->socket_path;
        } else {
            ngx_str_set(&conf->socket_path, "/var/run/waffynx.sock");
        }
    }

    return NGX_CONF_OK;
}

/* ------------------------------------------------------------------ */
/*  nginx.conf directives                                              */
/* ------------------------------------------------------------------ */
static ngx_command_t ngx_http_waffynx_commands[] = {

    { ngx_string("waffynx"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waffynx_loc_conf_t, enabled),
      NULL },

    { ngx_string("waffynx_socket"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waffynx_loc_conf_t, socket_path),
      NULL },

    { ngx_string("waffynx_timeout"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waffynx_loc_conf_t, timeout),
      NULL },

    { ngx_string("waffynx_fail_open"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waffynx_loc_conf_t, fail_open),
      NULL },

    { ngx_string("waffynx_max_body_size"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waffynx_loc_conf_t, max_body_size),
      NULL },

    ngx_null_command
};

/* ------------------------------------------------------------------ */
/*  Module context                                                     */
/* ------------------------------------------------------------------ */
static ngx_http_module_t ngx_http_waffynx_module_ctx = {
    NULL,                              /* preconfiguration */
    ngx_http_waffynx_init,            /* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */

    ngx_http_waffynx_create_loc_conf, /* create location conf */
    ngx_http_waffynx_merge_loc_conf   /* merge location conf */
};

/* ------------------------------------------------------------------ */
/*  Module definition                                                  */
/* ------------------------------------------------------------------ */
ngx_module_t ngx_http_waffynx_module = {
    NGX_MODULE_V1,
    &ngx_http_waffynx_module_ctx,     /* module context */
    ngx_http_waffynx_commands,        /* module directives */
    NGX_HTTP_MODULE,                  /* module type */
    NULL,                             /* init master */
    NULL,                             /* init module */
    NULL,                             /* init process */
    NULL,                             /* init thread */
    NULL,                             /* exit thread */
    NULL,                             /* exit process */
    NULL,                             /* exit master */
    NGX_MODULE_V1_PADDING
};
