local PLUGIN_NAME = "ja4h-fingerprint"

package.loaded["resty.sha256"] = {
  new = function()
    local state = ""
    return {
      reset = function()
        state = ""
      end,
      update = function(_, value)
        state = value
      end,
      final = function()
        return state
      end,
    }
  end,
}

package.loaded["resty.string"] = {
  to_hex = function(value)
    local hex = {}
    for i = 1, #value do
      hex[#hex + 1] = string.format("%02x", string.byte(value, i))
    end
    return table.concat(hex)
  end,
}

_G.test_service_headers = {}
_G.test_response_headers = {}
_G.test_headers = {}
_G.test_method = "GET"
_G.test_http_version = 1.1

_G.kong = {
  ctx = {
    plugin = {},
  },
  request = {
    get_method = function()
      return _G.test_method
    end,
    get_headers = function()
      return _G.test_headers
    end,
    get_http_version = function()
      return _G.test_http_version
    end,
  },
  service = {
    request = {
      set_header = function(name, value)
        _G.test_service_headers[name] = value
      end,
    },
  },
  response = {
    set_header = function(name, value)
      _G.test_response_headers[name] = value
    end,
  },
}

local function load_handler()
  local handler_path = "kong.plugins." .. PLUGIN_NAME .. ".handler"
  package.loaded[handler_path] = nil
  return require(handler_path)
end

local function reset_state()
  _G.test_service_headers = {}
  _G.test_response_headers = {}
  _G.test_headers = {}
  _G.test_method = "GET"
  _G.test_http_version = 1.1
  _G.kong.ctx.plugin = {}
end

local function base_config(overrides)
  local config = {
    header_name = "X-JA4H-Fingerprint",
    include_raw = false,
    response_debug_headers = false,
    ignore_headers = nil,
    trim_xff_header_count = 0,
    http_version_custom_header = nil,
  }

  if overrides then
    for key, value in pairs(overrides) do
      config[key] = value
    end
  end

  return config
end

describe(PLUGIN_NAME .. ": unit tests", function()
  local handler

  lazy_setup(function()
    handler = load_handler()
  end)

  before_each(function()
    reset_state()
  end)

  it("generates a fingerprint for regular string headers", function()
    _G.test_headers = {
      ["accept-language"] = "en-US,en;q=0.9",
      ["cookie"] = "foo=bar; baz=qux",
      ["referer"] = "https://example.test",
      ["user-agent"] = "curl/8.0",
    }

    handler:access(base_config())

    assert.is_string(_G.test_service_headers["X-JA4H-Fingerprint"])
    assert.is_truthy(_G.kong.ctx.plugin.ja4h_fingerprint)
  end)

  it("ignores multi-value Cookie headers instead of crashing", function()
    _G.test_headers = {
      ["cookie"] = { "foo=bar", "baz=qux" },
      ["user-agent"] = "curl/8.0",
    }

    handler:access(base_config({ include_raw = true }))

    assert.is_string(_G.test_service_headers["X-JA4H-Fingerprint"])
    assert.matches("_000000000000_000000000000$", _G.test_service_headers["X-JA4H-Fingerprint"])
    assert.is_string(_G.test_service_headers["X-JA4H-Fingerprint-Raw"])
  end)

  it("ignores multi-value Accept-Language headers instead of crashing", function()
    _G.test_headers = {
      ["accept-language"] = { "en-US", "nl-NL" },
      ["user-agent"] = "curl/8.0",
    }

    handler:access(base_config())

    assert.is_string(_G.test_service_headers["X-JA4H-Fingerprint"])
    assert.matches("20000_", _G.test_service_headers["X-JA4H-Fingerprint"], 1, true)
  end)

  it("ignores multi-value custom HTTP version headers instead of crashing", function()
    _G.test_headers = {
      ["x-http-version"] = { "HTTP/2", "HTTP/1.1" },
      ["user-agent"] = "curl/8.0",
    }
    _G.test_http_version = 1.1

    handler:access(base_config({ http_version_custom_header = "X-HTTP-Version" }))

    assert.matches("^ge11", _G.test_service_headers["X-JA4H-Fingerprint"])
  end)

  it("ignores multi-value X-Forwarded-For headers when trimming is enabled", function()
    _G.test_headers = {
      ["x-forwarded-for"] = { "1.1.1.1", "2.2.2.2" },
      ["user-agent"] = "curl/8.0",
    }

    handler:access(base_config({ trim_xff_header_count = 1 }))

    assert.is_string(_G.test_service_headers["X-JA4H-Fingerprint"])
  end)

  it("trims single-string X-Forwarded-For headers when configured", function()
    _G.test_headers = {
      ["x-forwarded-for"] = "1.1.1.1, 2.2.2.2, 3.3.3.3",
      ["user-agent"] = "curl/8.0",
    }

    handler:access(base_config({ include_raw = true, trim_xff_header_count = 1 }))

    assert.matches("x-forwarded-for,user-agent", _G.test_service_headers["X-JA4H-Fingerprint-Raw"], 1, true)
  end)
end)
