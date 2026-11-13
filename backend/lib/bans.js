import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import errs from "./error.js";

export const BAN_ACTIONS = [403, 404, 444];
export const MAX_BAN_TTL_SECONDS = 365 * 24 * 60 * 60;
export const DEFAULT_BAN_TTL_SECONDS = 3600;
export const MAX_ACTIVE_BANS = 5000;
const CONTROL_CHARS_RE = /\p{Cc}/u;

const CONTROL_DIR = process.env.NPM_BAN_CONTROL_DIR || "/run/nginx-pm-control";
export const BAN_SOCKET_PATH = path.join(CONTROL_DIR, "ban.sock");
export const BAN_SECRET_PATH = path.join(CONTROL_DIR, "ban.secret");
export const BAN_BACKUP_FILE = "/data/nginx/global/ip-bans.json";

/**
 * Formats epoch ms as "YYYY-MM-DD HH:MM:SS" UTC for SQLite + SQL DATETIME consistency.
 */
export const formatDbUtcDateTime = (ms) => new Date(ms).toISOString().slice(0, 19).replace("T", " ");

/**
 * Parses DB datetime values ("YYYY-MM-DD HH:MM:SS" UTC or ISO) to epoch milliseconds.
 */
export const parseDbUtcMs = (value) => {
	if (value instanceof Date) {
		return value.getTime();
	}
	if (typeof value !== "string") {
		return Number.NaN;
	}
	const trimmed = value.trim();
	if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(trimmed)) {
		return Date.parse(`${trimmed.replace(" ", "T")}Z`);
	}
	return Date.parse(trimmed);
};

/**
 * Validates and canonicalizes a single IPv4 or IPv6 address (no CIDR, whitespace, or controls).
 */
export const normalizeSingleIp = (value) => {
	if (typeof value !== "string") {
		throw new errs.ValidationError("ip must be a string");
	}
	if (CONTROL_CHARS_RE.test(value)) {
		throw new errs.ValidationError("Invalid single IP address (CIDR belongs in block-rules)");
	}
	const trimmed = value.trim();
	if (!trimmed || trimmed.length > 45 || /\s/.test(trimmed) || trimmed.includes("/")) {
		throw new errs.ValidationError("Invalid single IP address (CIDR belongs in block-rules)");
	}
	const family = net.isIP(trimmed);
	if (family === 0) {
		throw new errs.ValidationError(`Invalid IP address: ${trimmed}`);
	}
	if (family === 6) {
		return new URL(`http://[${trimmed}]/`).hostname.slice(1, -1).toLowerCase();
	}
	return trimmed;
};

/**
 * Validates and normalizes create-ban payload, resolving expiry from ttl_seconds or expires_on.
 */
export const validateBanInput = (data, nowMs = Date.now()) => {
	if (!data || typeof data !== "object") {
		throw new errs.ValidationError("Invalid ban payload");
	}
	if ("meta" in data && data.meta !== undefined) {
		throw new errs.ValidationError("meta is not writable via API");
	}
	const ip = normalizeSingleIp(data.ip);

	const action = data.action === undefined ? 403 : Number(data.action);
	if (!Number.isInteger(action) || !BAN_ACTIONS.includes(action)) {
		throw new errs.ValidationError(`action must be one of: ${BAN_ACTIONS.join(", ")}`);
	}

	let expiresMs;
	let ttlSeconds;
	if (data.expires_on !== undefined && data.expires_on !== null && data.expires_on !== "") {
		expiresMs = parseDbUtcMs(data.expires_on);
		if (!Number.isFinite(expiresMs)) {
			throw new errs.ValidationError("Invalid expires_on timestamp");
		}
		ttlSeconds = Math.ceil((expiresMs - nowMs) / 1000);
		if (ttlSeconds < 1 || ttlSeconds > MAX_BAN_TTL_SECONDS) {
			throw new errs.ValidationError(`expires_on must be 1..${MAX_BAN_TTL_SECONDS} seconds in the future`);
		}
	} else {
		ttlSeconds = data.ttl_seconds === undefined ? DEFAULT_BAN_TTL_SECONDS : Number(data.ttl_seconds);
		if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > MAX_BAN_TTL_SECONDS) {
			throw new errs.ValidationError(`ttl_seconds must be an integer between 1 and ${MAX_BAN_TTL_SECONDS}`);
		}
		expiresMs = nowMs + ttlSeconds * 1000;
	}

	const reason = typeof data.reason === "string" ? data.reason.trim() : "";
	if (reason.length > 500 || CONTROL_CHARS_RE.test(reason)) {
		throw new errs.ValidationError("reason must be at most 500 printable characters");
	}

	return {
		ip,
		action,
		expires_ms: expiresMs,
		expires_on: formatDbUtcDateTime(expiresMs),
		ttl_seconds: ttlSeconds,
		reason,
	};
};

/**
 * Generates a salted SHA-256 verifier string for storing a ban-agent bearer token hash.
 */
export const createTokenVerifier = (rawToken) => {
	const salt = crypto.randomBytes(16).toString("hex");
	const digest = crypto.createHash("sha256").update(`${salt}:${rawToken}`).digest("hex");
	return `${salt}:${digest}`;
};

/**
 * Constant-time verification of a bearer token against a stored salted SHA-256 verifier.
 */
export const verifyTokenVerifier = (rawToken, stored) => {
	if (typeof rawToken !== "string" || typeof stored !== "string") {
		return false;
	}
	const sep = stored.indexOf(":");
	if (sep <= 0) {
		return false;
	}
	const salt = stored.slice(0, sep);
	const expectedHex = stored.slice(sep + 1);
	if (!salt || !/^[0-9a-f]{64}$/i.test(expectedHex)) {
		return false;
	}
	const actualBuf = crypto.createHash("sha256").update(`${salt}:${rawToken}`).digest();
	const expectedBuf = Buffer.from(expectedHex, "hex");
	return actualBuf.length === expectedBuf.length && crypto.timingSafeEqual(actualBuf, expectedBuf);
};

/**
 * Derives authoritative ban audit source strictly from verified caller identity.
 */
export const deriveBanSource = (access) => {
	const agent = typeof access?.getBanAgent === "function" ? access.getBanAgent() : null;
	if (agent?.label) {
		return `agent:${agent.id}:${agent.label}`.slice(0, 64);
	}
	return "manual";
};

const assertSafeDir = (dirPath) => {
	let st;
	try {
		st = fs.lstatSync(dirPath);
	} catch (err) {
		if (err.code === "ENOENT") {
			return false;
		}
		throw err;
	}
	if (st.isSymbolicLink() || !st.isDirectory()) {
		throw new Error(`Unsafe ban control directory: ${dirPath}`);
	}
	if ((st.mode & 0o077) !== 0) {
		throw new Error(`Ban control directory permissions too broad: ${dirPath}`);
	}
	return true;
};

/**
 * Reads runtime shared secret cleanly without logging its value.
 * Returns null if runtime control files are absent (e.g. non-container unit test).
 */
export const readBanSecret = (controlDir = CONTROL_DIR) => {
	if (!assertSafeDir(controlDir)) {
		return null;
	}
	const secretPath = path.join(controlDir, "ban.secret");
	let st;
	try {
		st = fs.lstatSync(secretPath);
	} catch (err) {
		if (err.code === "ENOENT") {
			return null;
		}
		throw err;
	}
	if (st.isSymbolicLink() || !st.isFile()) {
		throw new Error(`Unsafe ban secret path: ${secretPath}`);
	}
	if ((st.mode & 0o077) !== 0) {
		throw new Error(`Ban secret file permissions too broad: ${secretPath}`);
	}
	const secret = fs.readFileSync(secretPath, "utf8").trim();
	return secret.length >= 32 ? secret : null;
};

/**
 * Verifies the Unix domain socket exists safely (real socket, not symlink, safe dir).
 */
export const assertSafeSocket = (controlDir = CONTROL_DIR) => {
	if (!assertSafeDir(controlDir)) {
		return null;
	}
	const sockPath = path.join(controlDir, "ban.sock");
	let st;
	try {
		st = fs.lstatSync(sockPath);
	} catch (err) {
		if (err.code === "ENOENT") {
			return null;
		}
		throw err;
	}
	if (st.isSymbolicLink() || !st.isSocket()) {
		throw new Error(`Unsafe ban socket path: ${sockPath}`);
	}
	return sockPath;
};

/**
 * Sends a bounded JSON request to the OpenResty Lua unix control socket.
 */
export const sendLuaBanControl = (method, reqPath, payload = null, controlDir = CONTROL_DIR) =>
	new Promise((resolve, reject) => {
		let secret;
		let sockPath;
		try {
			secret = readBanSecret(controlDir);
			sockPath = assertSafeSocket(controlDir);
		} catch (err) {
			reject(err);
			return;
		}
		if (!secret || !sockPath) {
			resolve({ available: false });
			return;
		}

		const body = payload === null ? null : JSON.stringify(payload);
		const headers = {
			"X-NPM-Ban-Secret": secret,
			Host: "localhost",
		};
		if (body !== null) {
			headers["Content-Type"] = "application/json";
			headers["Content-Length"] = Buffer.byteLength(body);
		}

		const req = http.request(
			{
				socketPath: sockPath,
				path: reqPath,
				method,
				agent: false,
				headers,
				timeout: 3000,
			},
			(res) => {
				const chunks = [];
				res.on("data", (chunk) => chunks.push(chunk));
				res.on("end", () => {
					const text = Buffer.concat(chunks).toString("utf8");
					let parsed = null;
					try {
						parsed = text ? JSON.parse(text) : {};
					} catch {
						reject(new Error(`Invalid JSON from ban socket (HTTP ${res.statusCode})`));
						return;
					}
					if (res.statusCode >= 200 && res.statusCode < 300) {
						resolve({ available: true, ...parsed });
					} else {
						reject(new Error(parsed?.error || `Ban socket HTTP ${res.statusCode}`));
					}
				});
			},
		);

		req.on("timeout", () => {
			req.destroy(new Error("Ban socket request timeout"));
		});
		req.on("error", reject);

		if (body !== null) {
			req.write(body);
		}
		req.end();
	});

/**
 * Writes active unexpired bans atomically for fast nginx worker startup/restart rehydration.
 */
export const writeBanBackupFile = (bans, filePath = BAN_BACKUP_FILE) => {
	const dir = path.dirname(filePath);
	fs.mkdirSync(dir, { recursive: true });
	const tmp = `${filePath}.tmp-${process.pid}-${Date.now()}`;
	const data = JSON.stringify(
		bans.map((b) => ({
			id: b.id,
			ip: b.ip,
			action: b.action,
			expires_ms: b.expires_ms,
		})),
	);
	fs.writeFileSync(tmp, data, { encoding: "utf8", mode: 0o600 });
	fs.renameSync(tmp, filePath);
};
