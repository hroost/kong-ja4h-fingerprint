local typedefs = require "kong.db.schema.typedefs"

local PLUGIN_NAME = "ja4h-fingerprint"

local schema = {
  name = PLUGIN_NAME,
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { header_name = {
              type = "string",
              default = "X-JA4H-Fingerprint",
              description = "Header name to store the JA4H fingerprint"
          }},
          { http_version_custom_header = {
              type = "string",
              description = "Custom header name containing HTTP version"
          }},
          { ignore_headers = {
              type = "array",
              elements = { type = "string" },
              description = "List of headers to ignore"
          }},
          { trim_xff_header_count = {
              type = "integer",
              default = 0,
              description = "Number of X-Forwarded-For IPs to trim " ..
                            "(from the right side). In case of reverse-proxy " ..
                            "in front of the Kong"
          }},
          { include_raw = {
              type = "boolean",
              default = false,
              description = "Include raw fingerprint components in X-JA4H-Raw header"
          }},
          { response_debug_headers = {
            type = "boolean",
            default = false,
            description = "When true, add JA4H fingerprint and raw headers to the downstream response"
          }},
        },
      },
    },
  },
}

return schema
