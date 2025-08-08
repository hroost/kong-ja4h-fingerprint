-- JA4H Fingerprinting Plugin for Kong Gateway
-- Based on: https://github.com/FoxIO-LLC/ja4

local resty_sha256 = require "resty.sha256"
local str = require "resty.string"
local kong = kong
local string = string
local table = table

local plugin = {
  PRIORITY = 1000,
  VERSION = "0.1.0",
}

-- Pre-compile patterns for better performance
local COOKIE_PATTERN = "[^;]+"
local WHITESPACE_PATTERN = "^%s*"
local COOKIE_PAIR_PATTERN = "([^=]+)=?(.*)"
local NON_ALPHANUM_PATTERN = '%W'

-- Constants for performance
local EMPTY_HASH = '000000000000'
local DEFAULT_LANG = '0000'

-- Check if string starts with specific prefix
local function starts_with(value, start)
  return type(value) == 'string' and type(start) == 'string' and string.sub(value, 1, #start) == start
end

-- Collect all request data once for performance
local function collect_request_data(conf)
  local data = {
    method = kong.request.get_method(),
    headers = kong.request.get_headers(),
  }

  -- Get HTTP version from custom header or Kong's native detection
  if conf and conf.http_version_custom_header then
    data.http_version_raw = data.headers[conf.http_version_custom_header]
    data.http_version = kong.request.get_http_version() -- fallback
  else
    data.http_version = kong.request.get_http_version()
  end

  return data
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

-- Get HTTP version code
local function http_version(request_data)
  local version

  -- Use custom header value if available, otherwise use Kong's detection
  if request_data.http_version_raw then
    local version_str = string.upper(request_data.http_version_raw)
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

-- Count headers excluding cookies, referer, and ignored headers (optimized with single loop)
local function header_count_and_names(headers, ignored_headers_lookup)
  local count = 0
  local header_names = {}

  for name, _ in pairs(headers) do
    local lower_name = string.lower(name)
    if not starts_with(lower_name, 'cookie') and  -- skip by standard
       lower_name ~= 'referer' and                -- skip by standard
       not ignored_headers_lookup[lower_name] then
      count = count + 1
      table.insert(header_names, lower_name)
    end
  end

  return count, header_names
end

-- Check if referer header is set
local function referer_is_set(headers)
  return headers["referer"] and 'r' or 'n'
end

-- Check if cookie header is set
local function cookie_is_set(headers)
  return headers["cookie"] and 'c' or 'n'
end

-- Get first 4 characters of accept-language header (alphanumeric only)
local function accept_lang_beg(headers)
  local al = headers["accept-language"]
  if not al then
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
  if not cookie_header then
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

-- Main fingerprinting function (heavily optimized)
local function generate_ja4h_fingerprint(conf)
  -- Collect all request data once
  local request_data = collect_request_data(conf)
  local headers = request_data.headers
  local cookie_header = headers["cookie"]

  -- Create ignored headers lookup table
  local ignored_headers_lookup = create_ignored_headers_lookup(conf.ignore_headers)

  -- Get basic components
  local p1 = method_code(request_data)
  local p2 = http_version(request_data)
  local p3 = cookie_is_set(headers)
  local p4 = referer_is_set(headers)
  local p6 = accept_lang_beg(headers)

  -- Combined header processing with ignored headers filtering
  local header_count_val, header_names = header_count_and_names(headers, ignored_headers_lookup)
  -- Cap header count at 99 per requirement (clients with >=99 headers are treated as 99)
  local capped_header_count = header_count_val > 99 and 99 or header_count_val
  local p5 = tostring(capped_header_count)

  -- Combined cookie processing
  local p8_pretty, p9_pretty = parse_cookies(cookie_header)

  -- Generate hashes
  local p7_pretty = table.concat(header_names, ',')
  local p7 = truncated_sha256(p7_pretty)
  local p8 = truncated_sha256(p8_pretty)
  local p9 = truncated_sha256(p9_pretty)

  -- Optimized string building using table.concat for better performance
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


-- #TODO
-- x-forwarded-for will contain GLB IPs and should be stripped for accurate fingerprinting
