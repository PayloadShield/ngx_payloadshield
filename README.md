# ngx_payloadshield

`ngx_payloadshield_module` is an Nginx HTTP dynamic-module prototype that decrypts the established PayloadShield request envelope before proxying and encrypts buffered upstream response bodies before returning them. Applications behind Nginx receive ordinary plaintext HTTP requests and return ordinary plaintext HTTP responses. The module is not production-certified; compile and integration-test it against the exact Nginx/OpenSSL builds and configuration used in deployment before handling real traffic.

## Data flow

```text
Client -- JSON {"encrypted":"..."} --> Nginx PayloadShield
       -- authenticated plaintext --> HTTP upstream
Client <-- JSON {"encrypted":"..."} -- Nginx PayloadShield
       <-- authenticated ciphertext -- HTTP upstream
```

The module supports FastAPI/Uvicorn, Node.js/PM2, PHP/Laravel/PHP-FPM, Java, Go, .NET, and other HTTP upstreams. The upstream application does not need PayloadShield code.

## Existing protocol

The module preserves the shared ComPyPS/ComPHPPS format documented in the PayloadShield cross-language guide. It does not add a new versioned envelope.

* The HTTP body is JSON with one string property: `{"encrypted":"<handler output>"}`. The response uses the same shape.
* `aes-gcm-256`: standard Base64 of `12-byte nonce || ciphertext || 16-byte tag`.
* `chacha20-poly1305`: standard Base64 of `12-byte nonce || ciphertext || 16-byte tag`.
* `rsa-hybrid`: standard Base64 of a JSON object with Base64 strings `key`, `nonce`, and `data`. `key` is an RSA-OAEP-SHA256-wrapped random 32-byte AES key; `nonce` is 12 bytes; `data` is AES-256-GCM ciphertext followed by its 16-byte tag. OAEP uses SHA-256 for OAEP and MGF1.

All plaintext bytes represent the JSON serialization produced by the corresponding PayloadShield handler. The envelope does not select an algorithm: `payloadshield_algorithm` is trusted static configuration for the location, and the client must use the same handler. Unsupported configured algorithms fail `nginx -t`; selection is never taken from untrusted request data. AES-GCM and ChaCha use the same shared 32-byte key in both directions. For RSA-Hybrid, the server private key decrypts requests encrypted to the matching server public key; the configured public key encrypts responses for the configured client recipient. These are distinct roles and need not be the same key pair.

## Algorithms and security

Crypto uses OpenSSL EVP APIs only. AEAD tag verification must succeed before plaintext is returned. Nonces and hybrid AES keys are generated with OpenSSL's cryptographic random generator. RSA uses EVP RSA-OAEP with SHA-256, never raw RSA payload encryption or PKCS#1 v1.5 encryption.

The Nginx-independent provider API is in `include/payloadshield_crypto.h`; provider implementations and the registry are under `crypto/`. Nginx code calls the generic provider API and does not implement cryptographic primitives. Keys and plaintext are not logged. OpenSSL/Nginx memory is not guaranteed to be locked or immune to process dumps; pool buffers can retain plaintext until request cleanup. Use TLS, access control, replay protection, careful worker/process isolation, and restrictive filesystem permissions as well. Payload encryption does not replace those controls.

## Directives

Directives are valid in `http`, `server`, and `location` contexts and inherit through Nginx configuration scopes.

| Directive | Meaning |
|---|---|
| `payloadshield on\|off` | Enable request and response processing. Default `off`. |
| `payloadshield_algorithm aes-gcm-256\|chacha20-poly1305\|rsa-hybrid` | Select one registered provider. Required when enabled. |
| `payloadshield_key file` | Symmetric key file for AES-GCM/ChaCha. Exactly 32 raw bytes or Base64 encoding of 32 bytes. |
| `payloadshield_private_key file` | RSA private PEM used to decrypt RSA-Hybrid requests. |
| `payloadshield_public_key file` | RSA public PEM for the response recipient in RSA-Hybrid. |
| `payloadshield_max_body_size size` | Maximum decrypted request and plaintext upstream response size. Default `10m`. |
| `payloadshield_buffer_response on\|off` | Must be `on`; whole-message response encryption requires buffering. Default `off` so omission fails `nginx -t`. |
| `payloadshield_fail_open on\|off` | Explicitly pass through a request/response when an eligible PayloadShield operation fails. Default `off`. Body-size violations always fail closed. This can expose plaintext or send encrypted input upstream; do not enable casually. |

All configured key files and provider-specific key requirements are validated during configuration loading (`nginx -t`). Symmetric key files may contain raw 32-byte keys or standard Base64; no key is hardcoded. `payloadshield_max_body_size` covers decoded request and upstream response plaintext. Set Nginx's `client_max_body_size` separately to allow the larger encrypted JSON request representation.

RSA PEM files should be unencrypted PEM for this initial implementation: public key in SubjectPublicKeyInfo form (`BEGIN PUBLIC KEY`) and private key in a format readable by OpenSSL `PEM_read_bio_PrivateKey`. Use RSA keys of at least 2048 bits. Protect private and symmetric key files (for example, owner-readable only, `chmod 600`); public recipient keys may be world-readable. Rotate keys with coordinated client changes and a controlled Nginx configuration reload. There is no client identity/key resolver yet: RSA-Hybrid response encryption uses one static configured client public key for a location.

## Nginx configuration

The module must be compiled against a compatible Nginx build. Start by recording the installed build options and version:

```sh
nginx -V 2>&1
```

Obtain the matching Nginx source release from the official Nginx source distribution (or the package source corresponding to your vendor build). Use the same relevant `./configure` options shown by `nginx -V`. `--with-compat` enables Nginx's dynamic-module compatibility support; it does not make a module compatible with every Nginx version or vendor patch set.

Install the platform's Nginx development/build prerequisites and OpenSSL development headers/libraries. The provider API uses OpenSSL EVP and links `libcrypto`; OpenSSL 1.1.1 or newer is required. Examples below assume a Linux shell and an Nginx source directory matching the installed server:

```sh
cd nginx-X.Y.Z
./configure --with-compat --add-dynamic-module=/path/to/ngx_payloadshield
make modules
```

If the installed build has other configure arguments that affect module compatibility, include them as well. The resulting file is `objs/ngx_http_payloadshield_module.so`. Install it in the module directory reported/used by your Nginx package, for example:

```sh
sudo install -D -m 0644 objs/ngx_http_payloadshield_module.so \
    /usr/lib/nginx/modules/ngx_http_payloadshield_module.so
```

Load it in the main context, before `events` and `http`:

```nginx
load_module modules/ngx_http_payloadshield_module.so;

http {
    upstream fastapi_backend {
        server 127.0.0.1:8000;
    }

    server {
        listen 443 ssl;

        location /api/ {
            gzip off;
            payloadshield on;
            payloadshield_algorithm aes-gcm-256;
            payloadshield_key /etc/payloadshield/server.key;
            payloadshield_max_body_size 10m;
            payloadshield_buffer_response on;
            proxy_pass http://fastapi_backend;
        }
    }
}
```

For ChaCha20-Poly1305, use `payloadshield_algorithm chacha20-poly1305;` with its own 32-byte symmetric key file. For RSA-Hybrid, use separate role-specific files:

```nginx
location /api/ {
    gzip off;
    payloadshield on;
    payloadshield_algorithm rsa-hybrid;
    payloadshield_private_key /etc/payloadshield/server-private.pem;
    payloadshield_public_key /etc/payloadshield/client-recipient-public.pem;
    payloadshield_max_body_size 10m;
    payloadshield_buffer_response on;
    proxy_pass http://fastapi_backend;
}
```

Clients encrypt requests to the public key matching `server-private.pem`; they decrypt responses using the private key matching `client-recipient-public.pem`. Use distinct client recipient keys per deployment/location if static recipient key sharing is unacceptable.

Validate and reload after installing the module/configuration:

```sh
nginx -t
nginx -s reload
```

## Upstream examples

The upstream sees decrypted JSON and returns ordinary JSON. No PayloadShield middleware is installed in the application.

FastAPI/Uvicorn:

```python
from fastapi import FastAPI

app = FastAPI()

@app.post("/api/echo")
async def echo(payload: dict):
    return {"received": payload}
```

Node.js/PM2:

```js
const express = require("express");
const app = express();
app.use(express.json());
app.post("/api/echo", (req, res) => res.json({ received: req.body }));
app.listen(3000, "127.0.0.1");
```

PHP/Laravel:

```php
Route::post('/api/echo', function (Illuminate\Http\Request $request) {
    return response()->json(['received' => $request->all()]);
});
```

The same proxy arrangement applies to Java, Go, .NET, and any HTTP upstream. The app should not receive the outer `encrypted` property: that JSON wrapper is removed at Nginx, and its authenticated plaintext JSON becomes the upstream request body.

## Body, status, compression, and streaming behavior

Request processing uses `ngx_http_read_client_request_body()` and handles chains, in-memory buffers, and request-body temporary-file buffers. The complete encrypted body is parsed and authenticated before the upstream body is replaced. The content length is updated, and stale transfer-encoding is removed. Bodyless requests (including ordinary GET/HEAD requests) pass through without decryption; a non-empty encrypted envelope is required for a payload-bearing request. Malformed envelopes, invalid tags, and size violations do not forward decrypted data; they produce a generic 400/413-style response. Unsupported static providers fail `nginx -t`. OpenSSL detail is not returned to clients.

Response processing buffers chains and file-backed buffers until the final buffer, encrypts the complete plaintext payload, and returns the established JSON envelope. It updates Content-Length behavior and lets Nginx frame the resulting body. Normal response status codes, including non-2xx upstream statuses, are retained. HEAD, 1xx, 204, and 304 responses bypass body encryption because they have no normal response body to encrypt. Empty response bodies are encrypted as empty plaintext for other statuses.

This first implementation does not define or implement streaming encryption. `payloadshield_buffer_response on` is mandatory; the whole response is buffered up to the configured limit. Crypto and temporary-file reads are synchronous in an Nginx worker, so size limits and upstream timeouts matter for latency and denial-of-service resistance. Disable this module for SSE, indefinite streams, and other streaming routes.

Nginx gzip is not automatically changed by this module. Set `gzip off;` in every protected location so ciphertext is never compressed. An upstream response that already carries non-identity `Content-Encoding` is rejected unless `payloadshield_fail_open on` explicitly requests bypass. Filter-order variations are checked again in the body filter. Compression of plaintext before encryption is not currently supported; configure those routes without gzip/content encoding. Do not remove or rewrite `Content-Encoding` manually to work around this restriction.

## Errors and operational notes

Configuration, unknown algorithm, or key errors fail `nginx -t`. Malformed encrypted requests are rejected without exposing cryptographic diagnostics. Authentication failure yields no plaintext. Oversized incoming encrypted bodies may also be rejected earlier by Nginx's `client_max_body_size`. Runtime response-buffer or crypto failures fail closed by terminating response processing; this initial version cannot replace an upstream status after headers have begun. Check the Nginx error log for the generic PayloadShield operation message, never enable payload/key logging, and keep `payloadshield_fail_open off` unless the data-exposure consequences are explicitly accepted.

Use HTTPS in addition to payload encryption. The current static RSA recipient key setup does not identify clients, provide replay prevention, or rotate keys automatically. OpenSSL and Nginx buffer plaintext in process memory; use OS controls to protect worker memory and core dumps.

## Source tree and extending providers

```text
config                         Nginx dynamic-module build registration
include/payloadshield_crypto.h Nginx-independent provider interface
include/payloadshield_envelope.h
include/payloadshield_module.h Nginx configuration/context types
crypto/                        EVP providers and central registry
src/                           Nginx module, request/response filters, envelope
tests/                         C crypto/provider unit tests
tests/integration/             Python client and plaintext echo-upstream suite
```

Crypto source files are discovered from `crypto/*.c` by the single Nginx `config` file. To add a provider, implement the `payloadshield_crypto_provider_t` operations in a new `crypto/my_algorithm.c`, add its provider symbol to `crypto/crypto_registry.c`, and add tests. No Nginx-specific headers or types belong in `crypto/`; this keeps providers reusable by future Apache or Cloudflare gateway adapters. Provider registration is compile-time/static; arbitrary source files are never loaded or compiled at runtime.

## Testing and current limitations

Run the provider unit tests from a Linux build environment with a C compiler and OpenSSL development files:

```sh
make -C tests test
```

The unit tests cover AES-GCM and ChaCha round-trips, nonce/ciphertext/tag mutation, wrong keys, empty payloads, oversized payload rejection, RSA-Hybrid round-trip/wrong keys/invalid key size/malformed input, unsupported providers, and the shared JSON envelope. They use generated RSA keys and randomized AEAD nonces, plus a fixed NIST AES-256-GCM decryption vector.

The integration suite needs a real compatible Nginx binary/module and Python `cryptography`. Install its dependency and run it after building the module:

```sh
python3 -m pip install -r tests/integration/requirements.txt
NGINX_BIN=/usr/sbin/nginx \
PAYLOADSHIELD_MODULE=/usr/lib/nginx/modules/ngx_http_payloadshield_module.so \
python3 -m unittest discover -s tests/integration -v
```

It verifies plaintext at the upstream, encrypted responses at the client, chunked requests, large request/response bodies, 200/201/400/401/404/500 statuses, empty responses, malformed request rejection, HEAD, 204, and `nginx -t` rejection of unknown algorithms, missing key files, and malformed RSA PEM. Fixed cross-language deterministic vectors for every provider are not yet included. Do not treat a successful module compilation or unit test as production readiness; run this suite against the exact target Nginx and inspect memory/header behavior before deployment.

Troubleshooting:

* `dlopen()`/module version errors: rebuild against the matching Nginx source/build options and check `nginx -V`; `--with-compat` is not universal ABI compatibility.
* `nginx -t` reports provider/key configuration errors: check the exact algorithm name, key file readability/format, symmetric key length, and RSA PEM role.
* 400 responses: verify the client sends the existing `{"encrypted":"..."}` envelope and matching PayloadShield serialization/key.
* 413 responses: check both `payloadshield_max_body_size` and Nginx `client_max_body_size`.
* Content-encoding errors: disable upstream/Nginx compression on the protected location; encrypted bytes must not be gzip-compressed.
* No response on a large/streamed route: whole-response buffering is required in this release; lower the response size or do not enable PayloadShield for that route.

### Docker installation

Prerequisite: [Docker](https://docs.docker.com/get-docker/) installed and running.

1. Pull the image for your Nginx version:

   ```sh
   docker pull kanduganesh/payloadshield-nginx:1.28.3
   ```

2. Run it (the container listens on port 8080 and runs as the non-root `nginx` user):

   ```sh
   docker run -d --name payloadshield -p 8080:8080 kanduganesh/payloadshield-nginx:1.28.3
   ```

3. Verify the configuration and that the module is loaded:

   ```sh
   docker exec payloadshield nginx -t
   docker exec payloadshield nginx -V
   curl http://localhost:8080/
   ```

4. Use your own configuration (it must keep the `load_module` line):

   ```sh
   docker run -d -p 8080:8080 \
     -v ./nginx.conf:/etc/nginx/nginx.conf:ro \
     kanduganesh/payloadshield-nginx:1.28.3
   ```

   ```nginx
   load_module /usr/lib/nginx/modules/ngx_http_payloadshield_module.so;
   ```

5. Stop and remove:

   ```sh
   docker rm -f payloadshield
   ```
