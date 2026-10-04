#include "payloadshield_envelope.h"
#include "payloadshield_module.h"

#include <stdint.h>
#include <openssl/crypto.h>

static ngx_http_output_header_filter_pt ngx_http_payloadshield_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_payloadshield_next_body_filter;

static ngx_int_t ngx_http_payloadshield_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_payloadshield_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_payloadshield_append_response(ngx_http_request_t *r,
    ngx_http_payloadshield_ctx_t *ctx, ngx_chain_t *in, size_t limit);
static ngx_chain_t *ngx_http_payloadshield_response_chain(ngx_http_request_t *r,
    const u_char *data, size_t length, ngx_flag_t last);
static ngx_int_t ngx_http_payloadshield_bypass_response(ngx_http_request_t *r,
    ngx_http_payloadshield_ctx_t *ctx, ngx_chain_t *in);
static void ngx_http_payloadshield_cleanup_response(void *data);

static void
ngx_http_payloadshield_cleanup_response(void *data)
{
    ngx_http_payloadshield_ctx_t *ctx = data;

    if (ctx->response_data != NULL) {
        OPENSSL_cleanse(ctx->response_data, ctx->response_capacity);
        ngx_free(ctx->response_data);
        ctx->response_data = NULL;
        ctx->response_len = 0;
        ctx->response_capacity = 0;
    }
}

void
ngx_http_payloadshield_response_init(void)
{
    ngx_http_payloadshield_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_payloadshield_header_filter;

    ngx_http_payloadshield_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_payloadshield_body_filter;
}

static ngx_int_t
ngx_http_payloadshield_header_filter(ngx_http_request_t *r)
{
    ngx_http_payloadshield_loc_conf_t *conf;
    ngx_http_payloadshield_ctx_t *ctx;
    ngx_table_elt_t *encoding;
    ngx_pool_cleanup_t *pool_cleanup;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_payloadshield_module);
    if (!conf->enable || r->header_only || r->headers_out.status == NGX_HTTP_NO_CONTENT
        || r->headers_out.status == NGX_HTTP_NOT_MODIFIED
        || (r->headers_out.status >= 100 && r->headers_out.status < 200))
    {
        return ngx_http_payloadshield_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_payloadshield_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_payloadshield_module);
    pool_cleanup = ngx_pool_cleanup_add(r->pool, 0);
    if (pool_cleanup == NULL) return NGX_ERROR;
    pool_cleanup->handler = ngx_http_payloadshield_cleanup_response;
    pool_cleanup->data = ctx;
    encoding = r->headers_out.content_encoding;
    if (encoding != NULL && encoding->value.len != 0
        && !(encoding->value.len == sizeof("identity") - 1
             && ngx_strncasecmp(encoding->value.data,
                                (u_char *) "identity",
                                sizeof("identity") - 1) == 0))
    {
        if (conf->fail_open) {
            ctx->response_bypass = 1;
            return ngx_http_payloadshield_next_header_filter(r);
        }
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "payloadshield refuses an upstream Content-Encoding");
        return NGX_ERROR;
    }

    r->headers_out.content_length_n = -1;
    if (r->headers_out.content_length != NULL) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }
    r->headers_out.content_type.len = sizeof("application/json") - 1;
    r->headers_out.content_type.data = (u_char *) "application/json";
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    return ngx_http_payloadshield_next_header_filter(r);
}

static ngx_int_t
ngx_http_payloadshield_append_response(ngx_http_request_t *r,
    ngx_http_payloadshield_ctx_t *ctx, ngx_chain_t *in, size_t limit)
{
    ngx_chain_t *chain;

    for (chain = in; chain != NULL; chain = chain->next) {
        ngx_buf_t *buf = chain->buf;
        off_t amount = ngx_buf_size(buf);
        size_t needed;
        size_t capacity;
        u_char *grown;

        if (amount < 0 || (uint64_t) amount > limit - ctx->response_len) {
            return NGX_ABORT;
        }
        needed = ctx->response_len + (size_t) amount;
        if (needed > ctx->response_capacity) {
            capacity = ctx->response_capacity == 0
                           ? ngx_min((size_t) 4096, limit)
                           : ctx->response_capacity;
            while (capacity < needed) {
                if (capacity > limit / 2) {
                    capacity = limit;
                    break;
                }
                capacity *= 2;
            }
            grown = ngx_alloc(capacity, r->connection->log);
            if (grown == NULL) {
                return NGX_ERROR;
            }
            if (ctx->response_len != 0) {
                ngx_memcpy(grown, ctx->response_data, ctx->response_len);
            }
            if (ctx->response_data != NULL) {
                OPENSSL_cleanse(ctx->response_data, ctx->response_capacity);
                ngx_free(ctx->response_data);
            }
            ctx->response_data = grown;
            ctx->response_capacity = capacity;
        }

        if (amount != 0) {
            if (ngx_buf_in_memory(buf)) {
                ngx_memcpy(ctx->response_data + ctx->response_len,
                           buf->pos, (size_t) amount);
            } else if (buf->in_file && buf->file != NULL) {
                ssize_t read = ngx_read_file(buf->file,
                    ctx->response_data + ctx->response_len,
                    (size_t) amount, buf->file_pos);
                if (read != amount) {
                    return NGX_ERROR;
                }
            } else {
                return NGX_ERROR;
            }
        }
        ctx->response_len = needed;
    }

    return NGX_OK;
}

static ngx_chain_t *
ngx_http_payloadshield_response_chain(ngx_http_request_t *r,
    const u_char *data, size_t length, ngx_flag_t last)
{
    ngx_buf_t *buf;
    ngx_chain_t *chain;
    u_char *copy;

    buf = ngx_calloc_buf(r->pool);
    chain = ngx_alloc_chain_link(r->pool);
    copy = ngx_pnalloc(r->pool, length == 0 ? 1 : length);
    if (buf == NULL || chain == NULL || copy == NULL) {
        return NULL;
    }
    if (length != 0) {
        ngx_memcpy(copy, data, length);
    }
    buf->pos = copy;
    buf->last = copy + length;
    buf->start = copy;
    buf->end = copy + (length == 0 ? 1 : length);
    buf->temporary = 1;
    buf->last_buf = last && r == r->main;
    buf->last_in_chain = last;
    chain->buf = buf;
    chain->next = NULL;
    return chain;
}

static ngx_int_t
ngx_http_payloadshield_bypass_response(ngx_http_request_t *r,
    ngx_http_payloadshield_ctx_t *ctx, ngx_chain_t *in)
{
    ngx_chain_t *first;
    ngx_chain_t *last;
    ngx_chain_t *copy;

    if (ctx->response_len == 0) {
        return ngx_http_payloadshield_next_body_filter(r, in);
    }
    first = ngx_http_payloadshield_response_chain(r, ctx->response_data,
                                                  ctx->response_len, 0);
    if (first == NULL) return NGX_ERROR;
    last = first;
    while (last->next != NULL) last = last->next;
    for (copy = in; copy != NULL; copy = copy->next) {
        ngx_chain_t *link = ngx_alloc_chain_link(r->pool);
        if (link == NULL) return NGX_ERROR;
        link->buf = copy->buf;
        link->next = NULL;
        last->next = link;
        last = link;
    }
    OPENSSL_cleanse(ctx->response_data, ctx->response_len);
    ctx->response_bypass = 1;
    return ngx_http_payloadshield_next_body_filter(r, first);
}

static ngx_int_t
ngx_http_payloadshield_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_payloadshield_loc_conf_t *conf;
    ngx_http_payloadshield_ctx_t *ctx;
    ngx_chain_t *output;
    payloadshield_buffer_t encrypted = { NULL, 0 };
    payloadshield_buffer_t envelope = { NULL, 0 };
    ngx_int_t rc;
    ngx_flag_t last = 0;
    int crypto_rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_payloadshield_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_payloadshield_module);
    if (!conf->enable || ctx == NULL || ctx->response_bypass || in == NULL) {
        return ngx_http_payloadshield_next_body_filter(r, in);
    }

    if (r->headers_out.content_encoding != NULL
        && r->headers_out.content_encoding->value.len != 0
        && !(r->headers_out.content_encoding->value.len == sizeof("identity") - 1
             && ngx_strncasecmp(r->headers_out.content_encoding->value.data,
                                (u_char *) "identity",
                                sizeof("identity") - 1) == 0))
    {
        if (conf->fail_open) {
            ctx->response_bypass = 1;
            return ngx_http_payloadshield_bypass_response(r, ctx, in);
        }
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "payloadshield refuses a response encoded after its header filter");
        return NGX_ERROR;
    }

    for (ngx_chain_t *chain = in; chain != NULL; chain = chain->next) {
        if (chain->buf->last_buf || chain->buf->last_in_chain) {
            last = 1;
        }
    }

    rc = ngx_http_payloadshield_append_response(r, ctx, in,
                                                conf->max_body_size);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "payloadshield response buffering failed");
        return NGX_ERROR;
    }
    if (!last) {
        return NGX_OK;
    }

    crypto_rc = payloadshield_crypto_encrypt((char *) conf->algorithm.data,
        &conf->crypto, ctx->response_data, ctx->response_len, &encrypted);
    if (crypto_rc == PAYLOADSHIELD_CRYPTO_OK
        && ngx_strcmp(conf->algorithm.data, "rsa-hybrid") != 0)
    {
        payloadshield_buffer_t raw = encrypted;
        crypto_rc = payloadshield_base64_encode_buffer(raw.data, raw.len,
                                                       &encrypted);
        payloadshield_buffer_free(&raw);
    }
    if (crypto_rc == PAYLOADSHIELD_CRYPTO_OK) {
        crypto_rc = payloadshield_envelope_wrap(encrypted.data, encrypted.len,
                                                &envelope);
    }
    payloadshield_buffer_free(&encrypted);
    if (crypto_rc != PAYLOADSHIELD_CRYPTO_OK) {
        if (conf->fail_open) {
            output = ngx_http_payloadshield_response_chain(r,
                ctx->response_data, ctx->response_len, 1);
            OPENSSL_cleanse(ctx->response_data, ctx->response_len);
            ctx->response_bypass = 1;
            if (output == NULL) return NGX_ERROR;
            return ngx_http_payloadshield_next_body_filter(r, output);
        }
        OPENSSL_cleanse(ctx->response_data, ctx->response_len);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "payloadshield response encryption failed");
        return NGX_ERROR;
    }

    output = ngx_http_payloadshield_response_chain(r, envelope.data,
                                                  envelope.len, 1);
    payloadshield_buffer_free(&envelope);
    OPENSSL_cleanse(ctx->response_data, ctx->response_len);
    if (output == NULL) return NGX_ERROR;

    return ngx_http_payloadshield_next_body_filter(r, output);
}