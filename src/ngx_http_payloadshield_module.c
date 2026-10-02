#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <limits.h>
#include "payloadshield_module.h"

static void *ngx_http_payloadshield_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_payloadshield_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_payloadshield_init(ngx_conf_t *cf);
static char *ngx_http_payloadshield_read_file(ngx_conf_t *cf,
    ngx_str_t *path, u_char **data, size_t *length);
static char *ngx_http_payloadshield_load_keys(ngx_conf_t *cf,
    ngx_http_payloadshield_loc_conf_t *conf);
static void ngx_http_payloadshield_cleanup(void *data);

static ngx_command_t ngx_http_payloadshield_commands[] = {
    { ngx_string("payloadshield"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_payloadshield_loc_conf_t, enable),
      NULL },
    { ngx_string("payloadshield_algorithm"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_payloadshield_loc_conf_t, algorithm),
      NULL },
    { ngx_string("payloadshield_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_payloadshield_loc_conf_t, key_file),
      NULL },
    { ngx_string("payloadshield_private_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_payloadshield_loc_conf_t, private_key_file),
      NULL },
    { ngx_string("payloadshield_public_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_payloadshield_loc_conf_t, public_key_file),
      NULL },
    { ngx_string("payloadshield_max_body_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_payloadshield_loc_conf_t, max_body_size),
      NULL },
    { ngx_string("payloadshield_buffer_response"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_payloadshield_loc_conf_t, buffer_response),
      NULL },
    { ngx_string("payloadshield_fail_open"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_payloadshield_loc_conf_t, fail_open),
      NULL },
      ngx_null_command
};

static ngx_http_module_t ngx_http_payloadshield_module_ctx = {
    NULL,
    ngx_http_payloadshield_init,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_payloadshield_create_loc_conf,
    ngx_http_payloadshield_merge_loc_conf
};

ngx_module_t ngx_http_payloadshield_module = {
    NGX_MODULE_V1,
    &ngx_http_payloadshield_module_ctx,
    ngx_http_payloadshield_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_payloadshield_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_payloadshield_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_payloadshield_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->buffer_response = NGX_CONF_UNSET;
    conf->fail_open = NGX_CONF_UNSET;
    conf->max_body_size = NGX_CONF_UNSET_SIZE;
    return conf;
}

static char *
ngx_http_payloadshield_read_file(ngx_conf_t *cf, ngx_str_t *path,
    u_char **data, size_t *length)
{
    BIO *bio;
    u_char *filename;
    u_char chunk[4096];
    u_char *contents = NULL;
    size_t used = 0;
    int count;

    filename = ngx_pnalloc(cf->pool, path->len + 1);
    if (filename == NULL) return NGX_CONF_ERROR;
    ngx_memcpy(filename, path->data, path->len);
    filename[path->len] = '\0';
    bio = BIO_new_file((char *) filename, "rb");
    if (bio == NULL) {
        return NGX_CONF_ERROR;
    }

    while ((count = BIO_read(bio, chunk, sizeof(chunk))) > 0) {
        u_char *grown;
        if (used > 1024 * 1024 - (size_t) count) {
            BIO_free(bio);
            return NGX_CONF_ERROR;
        }
        grown = ngx_pnalloc(cf->pool, used + (size_t) count);
        if (grown == NULL) {
            BIO_free(bio);
            return NGX_CONF_ERROR;
        }
        if (used != 0) {
            ngx_memcpy(grown, contents, used);
        }
        ngx_memcpy(grown + used, chunk, count);
        contents = grown;
        used += (size_t) count;
    }
    BIO_free(bio);
    if (count < 0 || used == 0) {
        return NGX_CONF_ERROR;
    }

    *data = contents;
    *length = used;
    return NGX_CONF_OK;
}

static int
ngx_http_payloadshield_parse_symmetric_key(ngx_conf_t *cf, u_char *data,
    size_t length, u_char **key, size_t *key_length)
{
    size_t start = 0;
    size_t end = length;
    u_char *decoded;
    u_char *key_copy;
    int decoded_length;
    size_t padding = 0;
    size_t i;

    if (length == 32) {
        key_copy = ngx_pnalloc(cf->pool, 32);
        if (key_copy == NULL) return 0;
        ngx_memcpy(key_copy, data, 32);
        *key = key_copy;
        *key_length = 32;
        return 1;
    }
    while (start < end && (data[start] == ' ' || data[start] == '\t'
           || data[start] == '\r' || data[start] == '\n')) start++;
    while (end > start && (data[end - 1] == ' ' || data[end - 1] == '\t'
           || data[end - 1] == '\r' || data[end - 1] == '\n')) end--;
    if (end == start || (end - start) % 4 != 0 || end - start > INT_MAX) {
        return 0;
    }
    for (i = start; i < end; i++) {
        u_char c = data[i];
        ngx_uint_t valid = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                           || (c >= '0' && c <= '9') || c == '+' || c == '/';
        if (c == '=') {
            if (i < end - 2) return 0;
        } else if (!valid || padding != 0) {
            return 0;
        }
        if (c == '=') padding++;
    }
    if (padding > 2) return 0;
    decoded = OPENSSL_malloc((end - start) / 4 * 3);
    if (decoded == NULL) {
        return 0;
    }
    decoded_length = EVP_DecodeBlock(decoded, data + start, (int) (end - start));
    if (decoded_length < 0 || decoded_length - (int) padding != 32) {
        OPENSSL_clear_free(decoded, (end - start) / 4 * 3);
        return 0;
    }
    *key = ngx_pnalloc(cf->pool, 32);
    if (*key == NULL) {
        OPENSSL_clear_free(decoded, (end - start) / 4 * 3);
        return 0;
    }
    ngx_memcpy(*key, decoded, 32);
    OPENSSL_clear_free(decoded, (end - start) / 4 * 3);
    *key_length = 32;
    return 1;
}

static void
ngx_http_payloadshield_cleanup(void *data)
{
    ngx_http_payloadshield_loc_conf_t *conf = data;
    if (conf->owned_key != NULL) {
        OPENSSL_cleanse(conf->owned_key, conf->crypto.key_len);
    }
    EVP_PKEY_free(conf->owned_private_key);
    EVP_PKEY_free(conf->owned_public_key);
}

static char *
ngx_http_payloadshield_load_keys(ngx_conf_t *cf,
    ngx_http_payloadshield_loc_conf_t *conf)
{
    u_char *bytes;
    u_char *parsed_key;
    size_t length;
    size_t parsed_key_length;
    BIO *bio;
    ngx_pool_cleanup_t *cleanup;
    ngx_flag_t loaded = 0;

    if (conf->crypto.key == NULL && conf->key_file.len != 0) {
        if (ngx_http_payloadshield_read_file(cf, &conf->key_file,
                                             &bytes, &length) != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }
        if (!ngx_http_payloadshield_parse_symmetric_key(cf, bytes, length,
            &parsed_key, &parsed_key_length))
        {
            OPENSSL_cleanse(bytes, length);
            return NGX_CONF_ERROR;
        }
        OPENSSL_cleanse(bytes, length);
        conf->owned_key = parsed_key;
        conf->crypto.key = parsed_key;
        conf->crypto.key_len = parsed_key_length;
        loaded = 1;
    }

    if (conf->crypto.private_key == NULL && conf->private_key_file.len != 0) {
        u_char *filename = ngx_pnalloc(cf->pool,
                           conf->private_key_file.len + 1);
        if (filename == NULL) return NGX_CONF_ERROR;
        ngx_memcpy(filename, conf->private_key_file.data,
               conf->private_key_file.len);
        filename[conf->private_key_file.len] = '\0';
        bio = BIO_new_file((char *) filename, "rb");
        if (bio == NULL) return NGX_CONF_ERROR;
        conf->crypto.private_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (conf->crypto.private_key == NULL) return NGX_CONF_ERROR;
        conf->owned_private_key = conf->crypto.private_key;
        loaded = 1;
    }

    if (conf->crypto.public_key == NULL && conf->public_key_file.len != 0) {
        u_char *filename = ngx_pnalloc(cf->pool,
                           conf->public_key_file.len + 1);
        if (filename == NULL) return NGX_CONF_ERROR;
        ngx_memcpy(filename, conf->public_key_file.data,
               conf->public_key_file.len);
        filename[conf->public_key_file.len] = '\0';
        bio = BIO_new_file((char *) filename, "rb");
        if (bio == NULL) return NGX_CONF_ERROR;
        conf->crypto.public_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (conf->crypto.public_key == NULL) return NGX_CONF_ERROR;
        conf->owned_public_key = conf->crypto.public_key;
        loaded = 1;
    }

    if (loaded) {
        cleanup = ngx_pool_cleanup_add(cf->pool, 0);
        if (cleanup == NULL) return NGX_CONF_ERROR;
        cleanup->handler = ngx_http_payloadshield_cleanup;
        cleanup->data = conf;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_payloadshield_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_payloadshield_loc_conf_t *prev = parent;
    ngx_http_payloadshield_loc_conf_t *conf = child;
    ngx_flag_t key_overridden = conf->key_file.data != NULL;
    ngx_flag_t private_key_overridden = conf->private_key_file.data != NULL;
    ngx_flag_t public_key_overridden = conf->public_key_file.data != NULL;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->buffer_response, prev->buffer_response, 0);
    ngx_conf_merge_value(conf->fail_open, prev->fail_open, 0);
    ngx_conf_merge_size_value(conf->max_body_size, prev->max_body_size,
                              10 * 1024 * 1024);
    ngx_conf_merge_str_value(conf->algorithm, prev->algorithm, "");
    ngx_conf_merge_str_value(conf->key_file, prev->key_file, "");
    ngx_conf_merge_str_value(conf->private_key_file, prev->private_key_file, "");
    ngx_conf_merge_str_value(conf->public_key_file, prev->public_key_file, "");
    if (!key_overridden) {
        conf->crypto.key = prev->crypto.key;
        conf->crypto.key_len = prev->crypto.key_len;
    }
    if (!private_key_overridden) {
        conf->crypto.private_key = prev->crypto.private_key;
    }
    if (!public_key_overridden) {
        conf->crypto.public_key = prev->crypto.public_key;
    }

    if (!conf->enable) return NGX_CONF_OK;
    if (conf->algorithm.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "payloadshield_algorithm is required when payloadshield is on");
        return NGX_CONF_ERROR;
    }
    if (!conf->buffer_response) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "payloadshield requires payloadshield_buffer_response on");
        return NGX_CONF_ERROR;
    }
    if (conf->max_body_size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "payloadshield_max_body_size must be greater than zero");
        return NGX_CONF_ERROR;
    }
    if (ngx_http_payloadshield_load_keys(cf, conf) != NGX_CONF_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "payloadshield failed to load configured key material");
        return NGX_CONF_ERROR;
    }
    conf->crypto.max_payload_size = conf->max_body_size;
    if (payloadshield_crypto_validate_config((char *) conf->algorithm.data,
            &conf->crypto, 0) != PAYLOADSHIELD_CRYPTO_OK
        || payloadshield_crypto_validate_config((char *) conf->algorithm.data,
            &conf->crypto, 1) != PAYLOADSHIELD_CRYPTO_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "payloadshield algorithm or key configuration is invalid");
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_payloadshield_init(ngx_conf_t *cf)
{
    ngx_int_t rc;

    rc = ngx_http_payloadshield_request_init(cf);
    if (rc != NGX_OK) return rc;
    ngx_http_payloadshield_response_init();
    return NGX_OK;
}