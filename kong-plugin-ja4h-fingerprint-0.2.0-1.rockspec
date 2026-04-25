package = "kong-plugin-ja4h-fingerprint"
version = "0.2.0-1"
source = {
  url = "git://github.com/hroost/kong-ja4h-fingerprint",
}
description = {
  summary = "Kong plugin for generating JA4H HTTP client fingerprints",
  detailed = [[
      A Kong plugin that computes a JA4H fingerprint from HTTP request
      method and headers, and forwards it to upstream services.
  ]],
  homepage = "https://github.com/hroost/kong-ja4h-fingerprint",
  license = "MIT",
}
dependencies = {
  "lua >= 5.1",
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.ja4h-fingerprint.handler"] = "kong/plugins/ja4h-fingerprint/handler.lua",
    ["kong.plugins.ja4h-fingerprint.schema"] = "kong/plugins/ja4h-fingerprint/schema.lua",
  }
}
