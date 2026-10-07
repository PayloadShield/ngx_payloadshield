#ifndef PAYLOADSHIELD_MODULE_H
#define PAYLOADSHIELD_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "payloadshield_crypto.h"

typedef struct {
    ngx_flag_t enable;
    ngx_flag_t buffer_response;
    ngx_flag_t fail_open;
    ngx_str_t algorithm;
    ngx_str_t key_file;
    ngx_str_t private_key_file;
    ngx_str_t public_key_file;
    size_t max_body_size;
    payloadshield_crypto_config_t crypto;
    u_char *owned_key;
    EVP_PKEY *owned_private_key;
    EVP_PKEY *owned_public_key;
} ngx_http_payloadshield_loc_conf_t;

typedef struct {
    u_char *response_data;
    size_t response_len;
    size_t response_capacity;
    ngx_flag_t response_bypass;
    ngx_flag_t request_processed;
} ngx_http_payloadshield_ctx_t;

extern ngx_module_t ngx_http_payloadshield_module;

ngx_int_t ngx_http_payloadshield_request_init(ngx_conf_t *cf);
void ngx_http_payloadshield_response_init(void);

#endif