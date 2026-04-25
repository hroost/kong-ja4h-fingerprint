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
_G.test_raw_headers = ""

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

_G.ngx = {
  req = {
    raw_header = function()
      return _G.test_raw_headers
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
  _G.test_raw_headers = ""
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

local function clone_array(values)
  local copy = {}
  for i = 1, #values do
    copy[i] = values[i]
  end
  return copy
end

local function build_headers_from_order(order)
  local headers = {}
  for i = 1, #order do
    headers[order[i]] = "value-" .. tostring(i)
  end
  return headers
end

local function collect_pairs_order(headers)
  local names = {}
  for name, _ in pairs(headers) do
    names[#names + 1] = name
  end
  return names
end

local function join_names(names)
  return table.concat(names, ",")
end

local function build_raw_headers(order)
  local lines = {}
  for i = 1, #order do
    lines[i] = order[i] .. ": value-" .. tostring(i)
  end
  return table.concat(lines, "\r\n") .. "\r\n"
end

local function next_permutation(values)
  local i = #values - 1
  while i > 0 and values[i] >= values[i + 1] do
    i = i - 1
  end

  if i == 0 then
    return false
  end

  local j = #values
  while values[j] <= values[i] do
    j = j - 1
  end

  values[i], values[j] = values[j], values[i]

  local left = i + 1
  local right = #values
  while left < right do
    values[left], values[right] = values[right], values[left]
    left = left + 1
    right = right - 1
  end

  return true
end

local function find_pairs_order_mismatch()
  local order = {
    "x-h01",
    "x-h02",
    "x-h03",
    "x-h04",
    "x-h05",
    "x-h06",
    "x-h07",
    "x-h08",
    "x-h09",
    "x-h10",
  }

  for _ = 1, 200 do
    local headers = build_headers_from_order(order)
    local pairs_order = collect_pairs_order(headers)

    if join_names(order) ~= join_names(pairs_order) then
      return {
        request_order = clone_array(order),
        pairs_order = pairs_order,
        headers = headers,
      }
    end

    if not next_permutation(order) then
      break
    end
  end

  return nil
end

local PAIRS_ORDER_MISMATCH = find_pairs_order_mismatch()

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
    _G.test_raw_headers = "Accept-Language: en-US,en;q=0.9\r\nCookie: foo=bar; baz=qux\r\nReferer: https://example.test\r\nUser-Agent: curl/8.0\r\n"

    handler:access(base_config())

    assert.is_string(_G.test_service_headers["X-JA4H-Fingerprint"])
    assert.is_truthy(_G.kong.ctx.plugin.ja4h_fingerprint)
  end)

  it("merges repeated Cookie headers instead of crashing", function()
    _G.test_headers = {
      ["cookie"] = { "foo=bar", "baz=qux" },
      ["user-agent"] = "curl/8.0",
    }
    _G.test_raw_headers = "Cookie: foo=bar\r\nCookie: baz=qux\r\nUser-Agent: curl/8.0\r\n"

    handler:access(base_config({ include_raw = true }))

    assert.is_string(_G.test_service_headers["X-JA4H-Fingerprint"])
    assert.matches("^ge11cn", _G.test_service_headers["X-JA4H-Fingerprint"])
    assert.is_string(_G.test_service_headers["X-JA4H-Fingerprint-Raw"])
    assert.matches("_baz,foo_baz=qux,foo=bar$", _G.test_service_headers["X-JA4H-Fingerprint-Raw"])
  end)

  it("uses the first Accept-Language header when repeated", function()
    _G.test_headers = {
      ["accept-language"] = { "en-US", "nl-NL" },
      ["user-agent"] = "curl/8.0",
    }
    _G.test_raw_headers = "Accept-Language: en-US\r\nAccept-Language: nl-NL\r\nUser-Agent: curl/8.0\r\n"

    handler:access(base_config())

    assert.is_string(_G.test_service_headers["X-JA4H-Fingerprint"])
    assert.matches("3enus_", _G.test_service_headers["X-JA4H-Fingerprint"], 1, true)
  end)

  it("uses the first custom HTTP version header when repeated", function()
    _G.test_headers = {
      ["x-http-version"] = { "HTTP/2", "HTTP/1.1" },
      ["user-agent"] = "curl/8.0",
    }
    _G.test_http_version = 1.1
    _G.test_raw_headers = "X-HTTP-Version: HTTP/2\r\nX-HTTP-Version: HTTP/1.1\r\nUser-Agent: curl/8.0\r\n"

    handler:access(base_config({ http_version_custom_header = "X-HTTP-Version" }))

    assert.matches("^ge20", _G.test_service_headers["X-JA4H-Fingerprint"])
  end)

  it("ignores multi-value X-Forwarded-For headers when trimming is enabled", function()
    _G.test_headers = {
      ["x-forwarded-for"] = { "1.1.1.1", "2.2.2.2" },
      ["user-agent"] = "curl/8.0",
    }
    _G.test_raw_headers = "X-Forwarded-For: 1.1.1.1\r\nX-Forwarded-For: 2.2.2.2\r\nUser-Agent: curl/8.0\r\n"

    handler:access(base_config({ trim_xff_header_count = 1 }))

    assert.is_string(_G.test_service_headers["X-JA4H-Fingerprint"])
  end)

  it("trims single-string X-Forwarded-For headers when configured", function()
    _G.test_headers = {
      ["x-forwarded-for"] = "1.1.1.1, 2.2.2.2, 3.3.3.3",
      ["user-agent"] = "curl/8.0",
    }
    _G.test_raw_headers = "X-Forwarded-For: 1.1.1.1, 2.2.2.2, 3.3.3.3\r\nUser-Agent: curl/8.0\r\n"

    handler:access(base_config({ include_raw = true, trim_xff_header_count = 1 }))

    assert.matches("x-forwarded-for,user-agent", _G.test_service_headers["X-JA4H-Fingerprint-Raw"], 1, true)
  end)

  it("uses raw request header order for JA4H_b", function()
    _G.test_headers = {
      ["x-test-b"] = "two",
      ["x-test-a"] = "one",
    }
    _G.test_raw_headers = "X-Test-A: one\r\nX-Test-B: two\r\n"

    handler:access(base_config({ include_raw = true }))

    assert.matches("_x-test-a,x-test-b_", _G.test_service_headers["X-JA4H-Fingerprint-Raw"], 1, true)
  end)

  it("shows pairs-based header iteration diverges from request order for larger header sets", function()
    local mismatch = PAIRS_ORDER_MISMATCH
    if not mismatch then
      pending("No pairs order mismatch found in this Lua runtime")
    end
    local request_order_string = join_names(mismatch.request_order)
    local pairs_order_string = join_names(mismatch.pairs_order)

    assert.not_equals(request_order_string, pairs_order_string)
    assert.equals(10, #mismatch.request_order)
    assert.equals(10, #mismatch.pairs_order)
    assert.equals(request_order_string, join_names(mismatch.request_order))
    assert.equals(pairs_order_string, join_names(mismatch.pairs_order))
  end)

  it("uses raw request order instead of pairs order for JA4H_b with 10 headers", function()
    local mismatch = PAIRS_ORDER_MISMATCH
    if not mismatch then
      pending("No pairs order mismatch found in this Lua runtime")
    end
    _G.test_headers = mismatch.headers
    _G.test_raw_headers = build_raw_headers(mismatch.request_order)

    handler:access(base_config({ include_raw = true }))

    assert.matches(
      "_" .. join_names(mismatch.request_order) .. "_",
      _G.test_service_headers["X-JA4H-Fingerprint-Raw"],
      1,
      true
    )
    assert.not_matches(
      "_" .. join_names(mismatch.pairs_order) .. "_",
      _G.test_service_headers["X-JA4H-Fingerprint-Raw"],
      1,
      true
    )
  end)

  it("adds downstream response debug headers when enabled", function()
    _G.test_headers = {
      ["user-agent"] = "curl/8.0",
    }
    _G.test_raw_headers = "User-Agent: curl/8.0\r\n"

    handler:access(base_config({
      include_raw = false,
      response_debug_headers = true,
    }))

    assert.is_string(_G.test_response_headers["X-JA4H-Fingerprint"])
    assert.is_string(_G.test_response_headers["X-JA4H-Fingerprint-Raw"])
  end)

  it("falls back to kong.request.get_headers when raw headers are unavailable", function()
    _G.test_headers = {
      ["accept-language"] = "en-US,en;q=0.9",
      ["cookie"] = "foo=bar",
      ["user-agent"] = "curl/8.0",
    }
    _G.test_raw_headers = ""

    local original_raw_header = _G.ngx.req.raw_header
    _G.ngx.req.raw_header = function()
      error("raw_header unavailable")
    end

    handler:access(base_config({ include_raw = true }))

    _G.ngx.req.raw_header = original_raw_header

    assert.is_string(_G.test_service_headers["X-JA4H-Fingerprint"])
    assert.is_string(_G.test_service_headers["X-JA4H-Fingerprint-Raw"])
  end)

  it("excludes ignored headers from header count and JA4H_b", function()
    _G.test_headers = {
      ["x-ignore-me"] = "one",
      ["x-keep-me"] = "two",
      ["user-agent"] = "curl/8.0",
    }
    _G.test_raw_headers = "X-Ignore-Me: one\r\nX-Keep-Me: two\r\nUser-Agent: curl/8.0\r\n"

    handler:access(base_config({
      include_raw = true,
      ignore_headers = { "x-ignore-me" },
    }))

    assert.matches("20000_", _G.test_service_headers["X-JA4H-Fingerprint"], 1, true)
    assert.matches("_x-keep-me,user-agent_", _G.test_service_headers["X-JA4H-Fingerprint-Raw"], 1, true)
    assert.not_matches("_x-ignore-me,x-keep-me,user-agent_", _G.test_service_headers["X-JA4H-Fingerprint-Raw"], 1, true)
  end)

  it("removes X-Forwarded-For from JA4H when trimming drops all hops", function()
    _G.test_headers = {
      ["x-forwarded-for"] = "1.1.1.1",
      ["user-agent"] = "curl/8.0",
    }
    _G.test_raw_headers = "X-Forwarded-For: 1.1.1.1\r\nUser-Agent: curl/8.0\r\n"

    handler:access(base_config({
      include_raw = true,
      trim_xff_header_count = 1,
    }))

    assert.matches("10000_", _G.test_service_headers["X-JA4H-Fingerprint"], 1, true)
    assert.matches("_user-agent_", _G.test_service_headers["X-JA4H-Fingerprint-Raw"], 1, true)
    assert.not_matches("_x-forwarded-for,user-agent_", _G.test_service_headers["X-JA4H-Fingerprint-Raw"], 1, true)
  end)

  it("reuses fingerprint from kong.ctx.plugin on repeated access", function()
    _G.test_headers = {
      ["user-agent"] = "curl/8.0",
    }
    _G.test_raw_headers = "User-Agent: curl/8.0\r\n"

    handler:access(base_config({ include_raw = true }))

    local first_fingerprint = _G.test_service_headers["X-JA4H-Fingerprint"]
    local first_raw = _G.test_service_headers["X-JA4H-Fingerprint-Raw"]

    _G.test_service_headers = {}
    _G.test_headers = {
      ["user-agent"] = "different-agent",
      ["x-extra"] = "extra",
    }
    _G.test_raw_headers = "User-Agent: different-agent\r\nX-Extra: extra\r\n"

    handler:access(base_config({ include_raw = true }))

    assert.equals(first_fingerprint, _G.test_service_headers["X-JA4H-Fingerprint"])
    assert.equals(first_raw, _G.test_service_headers["X-JA4H-Fingerprint-Raw"])
  end)
end)
