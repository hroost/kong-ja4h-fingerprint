# JA4H HTTP Client Fingerprint Plugin

Kong plugin that computes a JA4H fingerprint from the incoming HTTP request and forwards it to the upstream service in a configurable header.

## What It Produces

The plugin generates a JA4H fingerprint in the form:

`JA4H_a_JA4H_b_JA4H_c_JA4H_d`

Where:
- `JA4H_a` is built from method, HTTP version, cookie presence, referer presence, header count, and the first 4 normalized characters of the primary `Accept-Language`
- `JA4H_b` is the truncated SHA256 hash of request header names in request order
- `JA4H_c` is the truncated SHA256 hash of sorted cookie names
- `JA4H_d` is the truncated SHA256 hash of sorted cookie name/value pairs

## Important Nuances

- `JA4H_b` is derived from `ngx.req.raw_header(true)` when available, not from iterating `kong.request.get_headers()` with `pairs()`. This is intentional: Lua table iteration does not preserve request header order, while JA4H expects header names in the order they appeared on the wire.
- The plugin parses raw request headers in a single ordered pass when OpenResty exposes them. This is the preferred path in Kong/OpenResty.
- Repeated `Cookie:` headers are merged and then parsed together.
- Repeated singleton-style headers such as `Accept-Language`, `Referer`, and the configured custom HTTP-version header use first-occurrence semantics in both the raw-header path and the fallback `get_headers()` path.
- `ignore_headers` entries are normalized case-insensitively, and `_` / `-` differences are treated as equivalent.
- If raw request headers are unavailable, the plugin falls back to `kong.request.get_headers()`. That fallback remains functional, but it cannot guarantee spec-accurate request-header ordering for `JA4H_b`.

## Configuration

Supported plugin config fields are defined in [schema.lua](kong/plugins/ja4h-fingerprint/schema.lua):

- `header_name`: upstream header used to store the JA4H fingerprint
- `http_version_custom_header`: optional header containing the effective HTTP version
- `ignore_headers`: headers excluded from the JA4H header-count and header-name hash
- `trim_xff_header_count`: removes a number of `X-Forwarded-For` hops from the right side before fingerprinting
- `include_raw`: also sends the raw JA4H components in `<header_name>-Raw`
- `response_debug_headers`: echoes fingerprint headers back in the downstream response

## Running In Kong

The repository contains a LuaRocks package file: [kong-plugin-ja4h-fingerprint-0.3.0-1.rockspec](kong-plugin-ja4h-fingerprint-0.3.0-1.rockspec).

A typical local flow is:

```bash
luarocks make kong-plugin-ja4h-fingerprint-0.3.0-1.rockspec
export KONG_PLUGINS=bundled,ja4h-fingerprint
kong start
```

Then enable the plugin as usual, for example:

```bash
curl -X POST http://127.0.0.1:8001/plugins \
  --data "name=ja4h-fingerprint" \
  --data "config.header_name=X-JA4H-Fingerprint"
```

If you are packaging Kong in a custom image, install the rock during image build and make sure `ja4h-fingerprint` is included in `KONG_PLUGINS`.

## Running In OpenResty

The fingerprinting logic depends on OpenResty request APIs, especially `ngx.req.raw_header(true)`, so the core logic is compatible with OpenResty-style Lua execution.

That said, this repository is packaged as a Kong plugin, not as a standalone OpenResty module with its own `init.lua`, nginx config snippets, or direct `content_by_lua` integration examples. So:

- the parsing logic is runnable in Kong because Kong is built on OpenResty
- it is likely reusable in plain OpenResty with light adaptation
- plain OpenResty usage is not a primary supported entrypoint in this repo today

## Tests

Tests live in [spec/ja4h-fingerprint/00-unit_spec.lua](spec/ja4h-fingerprint/00-unit_spec.lua).

The repo includes minimal Pongo and Busted scaffolding:
- [.pongo/pongorc](.pongo/pongorc)
- [.busted](.busted)

The test suite is intended to be run with Pongo in DB-less mode. Typical flow:

```bash
pongo run
```

If your environment already has `busted` available, you can also run the unit file directly:

```bash
busted spec/ja4h-fingerprint/00-unit_spec.lua
```

The tests cover:
- basic fingerprint generation
- repeated-header hardening
- ordered `JA4H_b` construction from raw request headers
- proof that plain Lua table iteration is not suitable for preserving request header order

The `pairs()`-divergence proof is opportunistic: it demonstrates the ordering problem when the current Lua runtime exposes a mismatch for the explored header set, while the core ordered-header tests do not depend on that mismatch existing.

## License

The source code in this repository is provided under the MIT license. See [LICENSE](LICENSE).

This does not waive or replace the licensing terms that apply to the JA4H / JA4+ algorithm itself. Use of software that implements JA4H may still be subject to FoxIO License 1.1 and any related commercial or OEM licensing requirements from FoxIO.

See also:
- [NOTICE](NOTICE)
- [FoxIO-LLC/ja4 licensing](https://github.com/FoxIO-LLC/ja4?tab=readme-ov-file#licensing)
- [JA4+ FoxIO License](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE)
