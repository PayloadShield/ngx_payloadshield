#include "payloadshield_envelope.h"
#include "payloadshield_module.h"

#include <stdint.h>
#include <openssl/crypto.h>

static ngx_int_t ngx_http_payloadshield_access_handler(ngx_http_request_t *r);
static void ngx_http_payloadshield_body_ready(ngx_http_request_t *r);
static ngx_int_t ngx_http_payloadshield_collect_request(ngx_http_request_t *r,
    u_char **data, size_t *length, size_t limit);
static ngx_int_t ngx_http_payloadshield_replace_request_body(
    ngx_http_request_t *r, const unsigned char *data, size_t length);

typedef struct {
    u_char *data;
    size_t length;
} ngx_http_payloadshield_plaintext_cleanup_t;

static void
ngx_http_payloadshield_cleanse_plaintext(void *data)
{
    ngx_http_payloadshield_plaintext_cleanup_t *cleanup = data;
    OPENSSL_cleanse(cleanup->data, cleanup->length);
}

ngx_int_t
ngx_http_payloadshield_request_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *handler;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    handler = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (handler == NULL) {
        return NGX_ERROR;
    }
    *handler = ngx_http_payloadshield_access_handler;
    return NGX_OK;
}

static ngx_int_t
ngx_http_payloadshield_access_handler(ngx_http_request_t *r)
{
    ngx_http_payloadshield_loc_conf_t *conf;
    ngx_int_t rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_payloadshield_module);
    if (!conf->enable) {
        return NGX_DECLINED;
    }
    if (r->headers_in.content_length_n <= 0
        && r->headers_in.transfer_encoding == NULL)
    {
        return NGX_DECLINED;
    }

    rc = ngx_http_read_client_request_body(r,
                                          ngx_http_payloadshield_body_ready);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    return NGX_DONE;
}

static ngx_int_t
ngx_http_payloadshield_collect_request(ngx_http_request_t *r,
    u_char **data, size_t *length, size_t limit)
{
    ngx_chain_t *chain;
    size_t total = 0;
    size_t offset = 0;
    u_char *buffer;

    if (r->request_body == NULL) {
        return NGX_ERROR;
    }

    for (chain = r->request_body->bufs; chain != NULL; chain = chain->next) {
        off_t amount = ngx_buf_size(chain->buf);

        if (amount < 0 || (uint64_t) amount > limit - total) {
            return NGX_ABORT;
        }
        total += (size_t) amount;
    }

    buffer = ngx_pnalloc(r->pool, total == 0 ? 1 : total);
    if (buffer == NULL) return NGX_ERROR;

    for (chain = r->request_body->bufs; chain != NULL; chain = chain->next) {
        ngx_buf_t *buf = chain->buf;
        off_t amount = ngx_buf_size(buf);
        if (amount != 0) {
            if (ngx_buf_in_memory(buf)) {
                ngx_memcpy(buffer + offset, buf->pos, (size_t) amount);
            } else if (buf->in_file && buf->file != NULL) {
                ssize_t read = ngx_read_file(buf->file, buffer + offset,
                                             (size_t) amount, buf->file_pos);
                if (read != amount) {
                    return NGX_ERROR;
                }
            } else {
                return NGX_ERROR;
            }
        }
        offset += (size_t) amount;
    }

    *data = buffer;
    *length = total;
    return NGX_OK;
}

static ngx_int_t
ngx_http_payloadshield_replace_request_body(ngx_http_request_t *r,
    const unsigned char *data, size_t length)
{
    ngx_buf_t *buf;
    ngx_chain_t *chain;
    u_char *body;
    u_char *content_length;
    u_char *end;
    ngx_pool_cleanup_t *pool_cleanup;
    ngx_http_payloadshield_plaintext_cleanup_t *cleanup;

    buf = ngx_calloc_buf(r->pool);
    chain = ngx_alloc_chain_link(r->pool);
    body = ngx_pnalloc(r->pool, length == 0 ? 1 : length);
    if (buf == NULL || chain == NULL || body == NULL) {
        return NGX_ERROR;
    }
    if (length != 0) {
        ngx_memcpy(body, data, length);
    }
    pool_cleanup = ngx_pool_cleanup_add(r->pool,
        sizeof(ngx_http_payloadshield_plaintext_cleanup_t));
    if (pool_cleanup == NULL) {
        OPENSSL_cleanse(body, length);
        return NGX_ERROR;
    }
    cleanup = pool_cleanup->data;
    cleanup->data = body;
    cleanup->length = length;
    pool_cleanup->handler = ngx_http_payloadshield_cleanse_plaintext;
    buf->pos = body;
    buf->last = body + length;
    buf->start = body;
    buf->end = body + (length == 0 ? 1 : length);
    buf->temporary = 1;
    buf->last_buf = 1;
    chain->buf = buf;
    chain->next = NULL;

    r->request_body->bufs = chain;
    r->request_body->temp_file = NULL;
    r->request_body->rest = 0;
    r->headers_in.content_length_n = (off_t) length;
    if (r->headers_in.transfer_encoding != NULL) {
        r->headers_in.transfer_encoding->hash = 0;
        r->headers_in.transfer_encoding = NULL;
    }
    r->headers_in.chunked = 0;
    if (r->headers_in.content_length != NULL) {
        content_length = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
        if (content_length == NULL) {
            return NGX_ERROR;
        }
        end = ngx_sprintf(content_length, "%O", (off_t) length);
        r->headers_in.content_length->value.data = content_length;
        r->headers_in.content_length->value.len = (size_t) (end - content_length);
    }

    return NGX_OK;
}

static void
ngx_http_payloadshield_body_ready(ngx_http_request_t *r)
{
    ngx_http_payloadshield_loc_conf_t *conf;
    payloadshield_buffer_t input = { NULL, 0 };
    payloadshield_buffer_t encoded = { NULL, 0 };
    payloadshield_buffer_t plaintext = { NULL, 0 };
    u_char *body = NULL;
    size_t body_length = 0;
    size_t input_limit;
    ngx_int_t rc;
    int crypto_rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_payloadshield_module);
    if (conf->max_body_size > (SIZE_MAX - 32768) / 2) {
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE);
        return;
    }
    input_limit = conf->max_body_size * 2 + 32768;
    rc = ngx_http_payloadshield_collect_request(r, &body, &body_length,
                                                input_limit);
    if (rc == NGX_ABORT) {
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE);
        return;
    }
    if (rc != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }

    rc = payloadshield_envelope_unwrap(body, body_length, &encoded);
    if (rc == PAYLOADSHIELD_CRYPTO_OK) {
        crypto_rc = payloadshield_crypto_decrypt(
            (char *) conf->algorithm.data, &conf->crypto,
            encoded.data, encoded.len, &plaintext);
    } else {
        crypto_rc = rc;
    }
    payloadshield_buffer_free(&encoded);

    if (crypto_rc == PAYLOADSHIELD_CRYPTO_OK
        && plaintext.len > conf->max_body_size)
    {
        payloadshield_buffer_free(&plaintext);
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE);
        return;
    }
    if (crypto_rc != PAYLOADSHIELD_CRYPTO_OK) {
        payloadshield_buffer_free(&plaintext);
        if (conf->fail_open && crypto_rc != PAYLOADSHIELD_CRYPTO_NOMEM) {
            ngx_http_core_run_phases(r);
            return;
        }
        ngx_http_finalize_request(r,
            crypto_rc == PAYLOADSHIELD_CRYPTO_NOMEM
                ? NGX_HTTP_INTERNAL_SERVER_ERROR
                : NGX_HTTP_BAD_REQUEST);
        return;
    }

    rc = ngx_http_payloadshield_replace_request_body(r, plaintext.data,
                                                      plaintext.len);
    payloadshield_buffer_free(&plaintext);
    if (rc != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    ngx_http_core_run_phases(r);
}