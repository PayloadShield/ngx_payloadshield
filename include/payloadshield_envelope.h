#ifndef PAYLOADSHIELD_ENVELOPE_H
#define PAYLOADSHIELD_ENVELOPE_H

#include "payloadshield_crypto.h"

int payloadshield_envelope_unwrap(const unsigned char *json, size_t json_len,
    payloadshield_buffer_t *encoded_payload);
int payloadshield_envelope_wrap(const unsigned char *encoded_payload,
    size_t encoded_payload_len, payloadshield_buffer_t *json);

#endif