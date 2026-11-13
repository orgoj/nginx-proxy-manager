local bit = require("bit")
local cjson = require("cjson.safe")
local ffi = require("ffi")

ffi.cdef[[
	int chmod(const char *pathname, unsigned int mode);
	int inet_pton(int af, const char *src, void *dst);
]]

local CONTROL_DIR = "/run/nginx-pm-control"
local SOCKET_PATH = CONTROL_DIR .. "/ban.sock"
local SECRET_PATH = CONTROL_DIR .. "/ban.secret"
local BACKUP_FILE = "/data/nginx/global/ip-bans.json"
local MAX_TTL = 31536000
local MAX_SYNC_BANS = 5000
local MAX_HIT_TAGS = 1000

local _M = {}
local cached_secret = nil
local inet_buf = ffi.new("uint8_t[16]")

local function load_secret()
	if cached_secret then
		return cached_secret
	end
	local f = io.open(SECRET_PATH, "rb")
	if not f then
		return nil
	end
	local raw = f:read("*a")
	f:close()
	if not raw then
		return nil
	end
	local trimmed = raw:gsub("%s+$", "")
	if #trimmed < 32 then
		return nil
	end
	cached_secret = trimmed
	return cached_secret
end

local function const_time_eq(a, b)
	if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b or #a == 0 then
		return false
	end
	local diff = 0
	for i = 1, #a do
		diff = bit.bor(diff, bit.bxor(a:byte(i), b:byte(i)))
	end
	return diff == 0
end

local function is_valid_ip(ip)
	if type(ip) ~= "string" or #ip == 0 or #ip > 45 then
		return false
	end
	if ip:find("[%s%c/]") then
		return false
	end
	return ffi.C.inet_pton(2, ip, inet_buf) == 1 or ffi.C.inet_pton(10, ip, inet_buf) == 1
end

local function is_valid_action(action)
	return action == 403 or action == 404 or action == 444
end

local function is_valid_int(val, min_v, max_v)
	if type(val) ~= "number" or math.floor(val) ~= val then
		return false
	end
	if min_v and val < min_v then
		return false
	end
	if max_v and val > max_v then
		return false
	end
	return true
end

local function rehydrate_from_file()
	local dict = ngx.shared.npm_bans
	if not dict then
		return
	end
	local f = io.open(BACKUP_FILE, "rb")
	if not f then
		return
	end
	local raw = f:read(2097152)
	f:close()
	if not raw or raw == "" then
		return
	end
	local rows = cjson.decode(raw)
	if type(rows) ~= "table" then
		return
	end
	if #rows > MAX_SYNC_BANS then
		ngx.log(ngx.ERR, "ip-bans backup exceeds MAX_SYNC_BANS (", #rows, " > ", MAX_SYNC_BANS, ")")
	end
	local now_ms = ngx.now() * 1000
	local count = 0
	for _, row in ipairs(rows) do
		if count >= MAX_SYNC_BANS then
			break
		end
		if type(row) == "table"
			and is_valid_int(row.id, 1)
			and is_valid_ip(row.ip)
			and is_valid_action(row.action)
			and type(row.expires_ms) == "number"
		then
			local ttl = math.ceil((row.expires_ms - now_ms) / 1000)
			if ttl >= 1 and ttl <= MAX_TTL then
				dict:set(row.ip, "ban" .. tostring(row.id) .. ":" .. tostring(row.action), ttl)
				count = count + 1
			end
		end
	end
end

function _M.init_worker()
	load_secret()
	if ngx.worker.id() == 0 then
		ngx.timer.at(0, function()
			ffi.C.chmod(SOCKET_PATH, 384) -- 0600 octal
			rehydrate_from_file()
		end)
	end
end

function _M.enforce_code()
	if ngx.req.is_internal() then
		return ""
	end
	if ngx.var.npm_blk_enabled ~= "1" then
		return ""
	end
	if ngx.var.npm_blk_acme == "1" or ngx.var.npm_blk_internal == "1" then
		return ""
	end
	local dict = ngx.shared.npm_bans
	if not dict then
		return ""
	end
	local ip = ngx.var.remote_addr
	if not ip or ip == "" then
		return ""
	end
	local val = dict:get(ip)
	if not val or type(val) ~= "string" then
		return ""
	end
	local rule_tag, code_str = val:match("^(ban%d+):(%d+)$")
	if rule_tag and code_str then
		ngx.var.npm_blk_rule = rule_tag
		return code_str
	end
	return ""
end

local function json_resp(status, obj)
	ngx.status = status
	ngx.header["Content-Type"] = "application/json"
	ngx.say(cjson.encode(obj))
	return ngx.exit(status)
end

local function is_authorized_control()
	local secret = load_secret()
	local provided = ngx.req.get_headers()["X-NPM-Ban-Secret"]
	return secret ~= nil and const_time_eq(provided, secret)
end

function _M.record_hit()
	if ngx.is_subrequest then
		return
	end
	local dict = ngx.shared.npm_blk_hits
	if not dict then
		return
	end
	local tag = ngx.var.npm_blk_rule
	if not tag or tag == "" then
		return
	end
	dict:incr("c:" .. tag, 1, 0)
	dict:set("t:" .. tag, ngx.time())
end

function _M.handle_hits()
	if not is_authorized_control() then
		return json_resp(401, { error = "unauthorized" })
	end
	if ngx.req.get_method() ~= "POST" then
		return json_resp(405, { error = "method_not_allowed" })
	end
	local dict = ngx.shared.npm_blk_hits
	if not dict then
		return json_resp(500, { error = "shared_dict_unavailable" })
	end

	ngx.req.read_body()
	local body = ngx.req.get_body_data()
	if not body or #body > 65536 then
		return json_resp(400, { error = "invalid_body" })
	end
	local ok_json, payload = pcall(cjson.decode, body)
	if not ok_json or type(payload) ~= "table" or type(payload.tags) ~= "table" then
		return json_resp(400, { error = "invalid_hits_payload" })
	end

	local count = 0
	local hits = {}
	for k, tag in pairs(payload.tags) do
		count = count + 1
		if count > MAX_HIT_TAGS then
			return json_resp(400, { error = "too_many_tags" })
		end
		if type(k) ~= "number" or type(tag) ~= "string" or #tag < 1 or #tag > 32 or not string.match(tag, "^[A-Za-z0-9_]+$") then
			return json_resp(400, { error = "invalid_tag" })
		end
		local c = tonumber(dict:get("c:" .. tag))
		local t = tonumber(dict:get("t:" .. tag))
		if (c and c > 0) or t then
			hits[tag] = { count = c or 0, last_hit = t }
		end
	end
	return json_resp(200, { ok = true, hits = hits })
end

function _M.handle_control()
	if not is_authorized_control() then
		return json_resp(401, { error = "unauthorized" })
	end

	local dict = ngx.shared.npm_bans
	if not dict then
		return json_resp(500, { error = "shared_dict_unavailable" })
	end

	local method = ngx.req.get_method()
	if method == "GET" then
		local epoch = dict:get("__epoch") or 0
		return json_resp(200, { ok = true, epoch = epoch })
	end
	if method ~= "POST" then
		return json_resp(405, { error = "method_not_allowed" })
	end

	ngx.req.read_body()
	local body = ngx.req.get_body_data()
	if not body or #body > 65536 then
		return json_resp(400, { error = "invalid_body" })
	end

	local payload = cjson.decode(body)
	if type(payload) ~= "table" or type(payload.op) ~= "string" then
		return json_resp(400, { error = "invalid_json" })
	end

	local op = payload.op
	if op == "set" then
		if #body > 4096
			or not is_valid_int(payload.id, 1)
			or not is_valid_ip(payload.ip)
			or not is_valid_action(payload.action)
			or not is_valid_int(payload.ttl, 1, MAX_TTL)
		then
			return json_resp(400, { error = "invalid_set_payload" })
		end
		local ok, err = dict:set(payload.ip, "ban" .. tostring(payload.id) .. ":" .. tostring(payload.action), payload.ttl)
		if not ok then
			return json_resp(500, { error = tostring(err) })
		end
		return json_resp(200, { ok = true })
	elseif op == "del" then
		if #body > 4096 or not is_valid_ip(payload.ip) then
			return json_resp(400, { error = "invalid_del_payload" })
		end
		dict:delete(payload.ip)
		return json_resp(200, { ok = true })
	elseif op == "sync" then
		if not is_valid_int(payload.epoch, 1) or type(payload.bans) ~= "table" or #payload.bans > MAX_SYNC_BANS then
			return json_resp(400, { error = "invalid_sync_payload" })
		end
		local validated = {}
		for i, item in ipairs(payload.bans) do
			if type(item) ~= "table"
				or not is_valid_int(item.id, 1)
				or not is_valid_ip(item.ip)
				or not is_valid_action(item.action)
				or not is_valid_int(item.ttl, 1, MAX_TTL)
			then
				return json_resp(400, { error = "invalid_ban_item", index = i })
			end
			validated[i] = item
		end
		dict:flush_all()
		for _, item in ipairs(validated) do
			dict:set(item.ip, "ban" .. tostring(item.id) .. ":" .. tostring(item.action), item.ttl)
		end
		dict:set("__epoch", payload.epoch)
		return json_resp(200, { ok = true, count = #validated, epoch = payload.epoch })
	end

	return json_resp(400, { error = "unsupported_op" })
end

return _M
