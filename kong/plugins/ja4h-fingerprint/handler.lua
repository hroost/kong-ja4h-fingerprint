-- JA4H Fingerprinting Plugin for Kong Gateway
-- Based on: https://github.com/FoxIO-LLC/ja4

local resty_sha256 = require "resty.sha256"
local str = require "resty.string"
local kong = kong
local string = string
local table = table
local ngx = ngx

local plugin = {
  PRIORITY = 1000,
  VERSION = "0.2.0",
}

-- Pre-compile patterns
local COOKIE_PATTERN = "[^;]+"
local WHITESPACE_PATTERN = "^%s*"
local COOKIE_PAIR_PATTERN = "([^=]+)=?(.*)"
local NON_ALPHANUM_PATTERN = '%W'

-- Constants for performance
local EMPTY_HASH = '000000000000'
local DEFAULT_LANG = '0000'
local HEADER_LINE_PATTERN = "([^\r\n]+)"
local HEADER_NAME_PATTERN = "^([^:]+):%s*(.*)$"

local function is_header_string(value)
  return type(value) == "string" and value ~= ""
end

local function get_raw_request_headers()
  if ngx and ngx.req and ngx.req.raw_header then
    local ok, raw_headers = pcall(ngx.req.raw_header, true)
    if ok and is_header_string(raw_headers) then
      return raw_headers
    end
  end
end

local function normalize_header_name(header_name)
  return string.lower(header_name):gsub("_", "-")
end

-- Check if string starts with specific prefix
local function starts_with(value, start)
  return type(value) == 'string' and type(start) == 'string' and string.sub(value, 1, #start) == start
end

-- Trim X-Forwarded-For header by removing specified number of IPs from the right side
local function trim_xff_header(xff_value, trim_count)
  if not is_header_string(xff_value) or trim_count <= 0 then
    return xff_value
  end

  -- Split by comma, handling both "," and ", " separators
  local ips = {}
  for ip in string.gmatch(xff_value, "([^,]+)") do
    -- Trim whitespace from each IP
    local trimmed_ip = string.match(ip, "^%s*(.-)%s*$")
    if trimmed_ip and trimmed_ip ~= "" then
      table.insert(ips, trimmed_ip)
    end
  end

  -- Remove specified number of IPs from the right side
  local total_ips = #ips
  local keep_count = total_ips - trim_count

  if keep_count <= 0 then
    -- If we're trimming more IPs than available, return empty string
    return nil
  end

  -- Reconstruct the header with remaining IPs
  local trimmed_ips = {}
  for i = 1, keep_count do
    table.insert(trimmed_ips, ips[i])
  end

  return table.concat(trimmed_ips, ",")
end

-- Create a lookup table for ignored headers for performance
local function create_ignored_headers_lookup(ignore_headers)
  if not ignore_headers or #ignore_headers == 0 then
    return {}
  end

  local lookup = {}
  for _, header in ipairs(ignore_headers) do
    lookup[string.lower(header)] = true
  end
  return lookup
end

local function collect_request_data_from_raw(conf, ignored_headers_lookup)
  local request_data = {
    method = kong.request.get_method(),
    http_version = kong.request.get_http_version(),
    cookie_header = nil,
    referer = nil,
    accept_language = nil,
    http_version_custom_header = nil,
    ordered_header_names = {},
    header_count = 0,
  }

  local raw_headers = get_raw_request_headers()
  if not is_header_string(raw_headers) then
    return
  end

  local custom_http_version_header
  if conf and is_header_string(conf.http_version_custom_header) then
    custom_http_version_header = normalize_header_name(conf.http_version_custom_header)
  end

  local xff_occurrences = {}

  for line in string.gmatch(raw_headers, HEADER_LINE_PATTERN) do
    local header_name, header_value = string.match(line, HEADER_NAME_PATTERN)
    if header_name then
      local normalized_name = normalize_header_name(header_name)

      if normalized_name == "cookie" then
        if request_data.cookie_header then
          request_data.cookie_header = request_data.cookie_header .. "; " .. header_value
        else
          request_data.cookie_header = header_value
        end

      elseif normalized_name == "referer" then
        if request_data.referer == nil then
          request_data.referer = header_value
        end

      elseif normalized_name == "accept-language" then
        if request_data.accept_language == nil then
          request_data.accept_language = header_value
        end

      elseif normalized_name == "x-forwarded-for" then
        xff_occurrences[#xff_occurrences + 1] = header_value
      end

      if custom_http_version_header and
         normalized_name == custom_http_version_header and
         request_data.http_version_custom_header == nil then
        request_data.http_version_custom_header = header_value
      end

      if normalized_name ~= "cookie" and
         normalized_name ~= "referer" and
         not ignored_headers_lookup[normalized_name] then
        request_data.header_count = request_data.header_count + 1
        table.insert(request_data.ordered_header_names, normalized_name)
      end
    end
  end

  if #xff_occurrences > 0 then
    request_data.x_forwarded_for = table.concat(xff_occurrences, ", ")
    if conf.trim_xff_header_count and conf.trim_xff_header_count > 0 then
      request_data.x_forwarded_for = trim_xff_header(
        request_data.x_forwarded_for,
        conf.trim_xff_header_count
      )
    end
  end

  if request_data.x_forwarded_for == nil and #xff_occurrences > 0 then
    local filtered_header_names = {}
    local removed = 0
    for i = 1, #request_data.ordered_header_names do
      local name = request_data.ordered_header_names[i]
      if name == "x-forwarded-for" then
        removed = removed + 1
      else
        filtered_header_names[#filtered_header_names + 1] = name
      end
    end
    request_data.ordered_header_names = filtered_header_names
    request_data.header_count = request_data.header_count - removed
  end

  return request_data
end

local function collect_request_data_from_headers(conf, ignored_headers_lookup)
  local headers = kong.request.get_headers()
  local request_data = {
    method = kong.request.get_method(),
    http_version = kong.request.get_http_version(),
    cookie_header = is_header_string(headers["cookie"]) and headers["cookie"] or nil,
    referer = headers["referer"],
    accept_language = is_header_string(headers["accept-language"]) and headers["accept-language"] or nil,
    ordered_header_names = {},
    header_count = 0,
  }

  if conf and is_header_string(conf.http_version_custom_header) then
    local custom_header_value = headers[normalize_header_name(conf.http_version_custom_header)]
    if is_header_string(custom_header_value) then
      request_data.http_version_custom_header = custom_header_value
    end
  end

  local xff_header = headers["x-forwarded-for"]
  if is_header_string(xff_header) then
    request_data.x_forwarded_for = xff_header
    if conf.trim_xff_header_count and conf.trim_xff_header_count > 0 then
      request_data.x_forwarded_for = trim_xff_header(
        request_data.x_forwarded_for,
        conf.trim_xff_header_count
      )
    end
  end

  for name, _ in pairs(headers) do
    local normalized_name = normalize_header_name(name)
    if not starts_with(normalized_name, "cookie") and
       normalized_name ~= "referer" and
       not ignored_headers_lookup[normalized_name] then
      if normalized_name ~= "x-forwarded-for" or request_data.x_forwarded_for ~= nil then
        request_data.header_count = request_data.header_count + 1
        table.insert(request_data.ordered_header_names, normalized_name)
      end
    end
  end

  return request_data
end

-- Collect all request data once
local function collect_request_data(conf)
  local ignored_headers_lookup = create_ignored_headers_lookup(conf.ignore_headers)

  local request_data = collect_request_data_from_raw(conf, ignored_headers_lookup)
  if request_data then
    return request_data, ignored_headers_lookup
  end

  return collect_request_data_from_headers(conf, ignored_headers_lookup), ignored_headers_lookup
end

-- Get HTTP version code
local function http_version(request_data)
  local version

  -- Use custom header value if available, otherwise use Kong's detection
  if request_data.http_version_custom_header then
    local version_str = string.upper(request_data.http_version_custom_header)
    if string.find(version_str, "HTTP/3") or string.find(version_str, "^3%.0") then
      version = 3.0
    elseif string.find(version_str, "HTTP/2") or string.find(version_str, "^2%.0") then
      version = 2.0
    elseif string.find(version_str, "HTTP/1%.1") or string.find(version_str, "^1%.1") then
      version = 1.1
    elseif string.find(version_str, "HTTP/1%.0") or string.find(version_str, "^1%.0") then
      version = 1.0
    else
      version = 1.0 -- default to HTTP/1.0 for unrecognized formats
    end
  else
    version = request_data.http_version
  end

  if version == 3.0 then
    return '30'
  elseif version == 2.0 then
    return '20'
  elseif version == 1.1 then
    return '11'
  else
    return '10'
  end
end

-- Get method code (first 2 characters, lowercase)
local function method_code(request_data)
  return string.sub(string.lower(request_data.method), 1, 2)
end

-- Check if referer header is set
local function referer_is_set(request_data)
  return request_data.referer and 'r' or 'n'
end

-- Check if cookie header is set
local function cookie_is_set(request_data)
  return request_data.cookie_header and 'c' or 'n'
end

-- Get first 4 characters of accept-language header (alphanumeric only)
local function accept_lang_beg(request_data)
  local al = request_data.accept_language
  if not is_header_string(al) then
    return DEFAULT_LANG
  end

  al = string.lower(al:gsub(NON_ALPHANUM_PATTERN, ''))
  local len = #al
  if len < 4 then
    return string.rep('0', 4 - len) .. al
  end
  return string.sub(al, 1, 4)
end

-- Parse cookies and get both sorted names and name=value pairs (combined for efficiency)
local function parse_cookies(cookie_header)
  if not is_header_string(cookie_header) then
    return '', ''
  end

  local cookie_names = {}
  local cookie_pairs = {}

  -- Single iteration through cookies
  for cookie_pair in string.gmatch(cookie_header, COOKIE_PATTERN) do
    local trimmed = cookie_pair:gsub(WHITESPACE_PATTERN, "")
    local name, value = string.match(trimmed, COOKIE_PAIR_PATTERN)
    if name then
      local lower_name = string.lower(name)
      table.insert(cookie_names, lower_name)
      table.insert(cookie_pairs, lower_name .. '=' .. (value or ''))
    end
  end

  table.sort(cookie_names)
  table.sort(cookie_pairs)

  return table.concat(cookie_names, ','), table.concat(cookie_pairs, ',')
end

-- Calculate truncated SHA256 hash (reuse digest instance for better performance)
local digest_instance = resty_sha256:new()
local function truncated_sha256(value)
  if #value == 0 then
    return EMPTY_HASH
  end

  digest_instance:reset()
  digest_instance:update(value)
  local hash = digest_instance:final()
  return string.sub(string.lower(str.to_hex(hash)), 1, 12)
end

-- Main fingerprinting function
local function generate_ja4h_fingerprint(conf)
  -- Collect all request data once
  local request_data = collect_request_data(conf)

  -- Get basic components
  local p1 = method_code(request_data)
  local p2 = http_version(request_data)
  local p3 = cookie_is_set(request_data)
  local p4 = referer_is_set(request_data)
  local p6 = accept_lang_beg(request_data)

  -- Cap header count at 99 per requirement (clients with >=99 headers are treated as 99)
  local capped_header_count = request_data.header_count > 99 and 99 or request_data.header_count
  local p5 = tostring(capped_header_count)

  -- Combined cookie processing
  local p8_pretty, p9_pretty = parse_cookies(request_data.cookie_header)

  -- Generate hashes
  local p7_pretty = table.concat(request_data.ordered_header_names, ',')
  local p7 = truncated_sha256(p7_pretty)
  local p8 = truncated_sha256(p8_pretty)
  local p9 = truncated_sha256(p9_pretty)

  local fingerprint_raw_parts = {
    p1, '_', p2, '_', p3, '_', p4, '_', p5, '_', p6, '_',
    p7_pretty, '_', p8_pretty, '_', p9_pretty
  }
  local fingerprint_parts = {
    p1, p2, p3, p4, p5, p6, '_', p7, '_', p8, '_', p9
  }

  return table.concat(fingerprint_parts), table.concat(fingerprint_raw_parts)
end

-- Plugin access phase
function plugin:access(conf)
  -- Check if fingerprint is already calculated by this plugin in current request
  if kong.ctx.plugin.ja4h_fingerprint then
    -- Reuse existing fingerprint
    kong.service.request.set_header(conf.header_name, kong.ctx.plugin.ja4h_fingerprint)

    if conf.include_raw and kong.ctx.plugin.ja4h_fingerprint_raw then
      kong.service.request.set_header(conf.header_name .. "-Raw", kong.ctx.plugin.ja4h_fingerprint_raw)
    end
    return
  end

  -- Calculate fingerprint for first time
  local fingerprint, fingerprint_raw = generate_ja4h_fingerprint(conf)

  -- Always store in context for reuse by other plugins/modules
  kong.ctx.plugin.ja4h_fingerprint = fingerprint
  kong.ctx.plugin.ja4h_fingerprint_raw = fingerprint_raw

  -- Set the main fingerprint header
  kong.service.request.set_header(conf.header_name, fingerprint)

  -- Optionally set the raw fingerprint header
  if conf.include_raw then
    kong.service.request.set_header(conf.header_name .. "-Raw", fingerprint_raw)
  end

  -- Set response debug headers
  if conf.response_debug_headers then
    kong.response.set_header(conf.header_name, fingerprint)
    kong.response.set_header(conf.header_name .. "-Raw", fingerprint_raw)
  end
end

return plugin
