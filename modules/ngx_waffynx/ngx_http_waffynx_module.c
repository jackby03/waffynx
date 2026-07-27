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

/* ------------------------------------------------------------------ */
/*  Configuration struct                                               */
/* ------------------------------------------------------------------ */
typedef struct {
    ngx_flag_t  enabled;
    ngx_str_t   socket_path;
    ngx_msec_t  timeout;
    ngx_uint_t  fail_open;    /* 1 = allow request if sidecar is down */
} ngx_http_waffynx_loc_conf_t;

/* ------------------------------------------------------------------ */
/*  Connect to the Go sidecar’s Unix socket                            */
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
/*  Build the HTTP request that we send to the Go sidecar              */
/* ------------------------------------------------------------------ */
static ssize_t
ngx_http_waffynx_build_request(ngx_http_request_t *r, u_char *buf, size_t size)
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
        return -1; /* buffer too small */
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
    code = (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');
    if (code > 999) {
        return NGX_ERROR;
    }

    *status = code;
    return NGX_OK;
}

/* ------------------------------------------------------------------ */
/*  ACCESS phase handler -- called for every request                   */
/* ------------------------------------------------------------------ */
static ngx_int_t
ngx_http_waffynx_access_handler(ngx_http_request_t *r)
{
    ngx_http_waffynx_loc_conf_t  *wlcf;
    u_char                        request_buf[4096];
    u_char                        response_buf[4096];
    ssize_t                       req_len, resp_len;
    ngx_int_t                     fd;
    ngx_uint_t                    status;

    /* ---- 1. Get our module config for this location ---- */
    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waffynx_module);
    if (wlcf == NULL || !wlcf->enabled) {
        return NGX_DECLINED; /* module disabled, pass through */
    }

    /* ---- 2. Build the HTTP request to send to sidecar ---- */
    req_len = ngx_http_waffynx_build_request(r, request_buf,
                                              sizeof(request_buf));
    if (req_len < 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waffynx: request buffer overflow");
        return wlcf->fail_open ? NGX_OK : NGX_HTTP_FORBIDDEN;
    }

    /* ---- 3. Connect to Go sidecar ---- */
    fd = ngx_http_waffynx_connect(&wlcf->socket_path, wlcf->timeout);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waffynx: cannot connect to sidecar at %V (errno=%d)",
                      &wlcf->socket_path, errno);
        return wlcf->fail_open ? NGX_OK : NGX_HTTP_FORBIDDEN;
    }

    /* ---- 4. Send the request ---- */
    if (send(fd, request_buf, (size_t) req_len, 0) != req_len) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waffynx: send() failed (errno=%d)", errno);
        (void) close(fd);
        return wlcf->fail_open ? NGX_OK : NGX_HTTP_FORBIDDEN;
    }

    /* ---- 5. Read the response ---- */
    resp_len = recv(fd, response_buf, sizeof(response_buf) - 1, 0);
    (void) close(fd);

    if (resp_len <= 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waffynx: recv() failed (errno=%d)", errno);
        return wlcf->fail_open ? NGX_OK : NGX_HTTP_FORBIDDEN;
    }
    response_buf[resp_len] = '\0';

    /* ---- 6. Parse the HTTP status code ---- */
    if (ngx_http_waffynx_parse_status(response_buf, resp_len,
                                       &status) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waffynx: could not parse sidecar response");
        return wlcf->fail_open ? NGX_OK : NGX_HTTP_FORBIDDEN;
    }

    /* ---- 7. Enforce verdict ---- */
    if (status == 204) {
        /* allow */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "waffynx: allowed request to %V", &r->uri);
        return NGX_OK;
    }

    /* deny */
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "waffynx: blocked request to %V (status=%ui)",
                  &r->uri, status);
    return NGX_HTTP_FORBIDDEN;
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

    if (conf->socket_path.len == 0) {
        ngx_str_set(&conf->socket_path, "/var/run/waffynx.sock");
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

    { ngx_string("waffynx_fail_mode"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      NULL, /* handled inline, simpler */
      0, 0, NULL },

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
