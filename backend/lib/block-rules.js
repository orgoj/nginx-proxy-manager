import net from "node:net";
import errs from "./error.js";

export const RULE_TYPES = ["ip", "ua", "uri", "uri_referer"];
export const RULE_ACTIONS = [403, 404, 444];
export const MAX_PATTERN_LENGTH = 512;
const MAX_GROUP_DEPTH = 4;
const MAX_QUANTIFIER_BOUND = 1000;

/**
 * Returns true if the string contains ASCII control characters (0x00..0x1f or 0x7f).
 */
export const hasControlChars = (value) => {
	for (let i = 0; i < value.length; i++) {
		const code = value.charCodeAt(i);
		if (code < 32 || code === 127) {
			return true;
		}
	}
	return false;
};

/**
 * Returns true when BLOCK_RULES env var disables global block enforcement.
 */
export const isBlockRulesEnabled = () => {
	const raw = (process.env.BLOCK_RULES || "on").trim().toLowerCase();
	return !["off", "false", "0", "no"].includes(raw);
};

/**
 * Validates and canonicalizes an IPv4/IPv6 address or CIDR range.
 * Throws ValidationError on invalid input.
 */
export const normalizeIpOrCidr = (value) => {
	if (typeof value !== "string") {
		throw new errs.ValidationError("IP/CIDR pattern must be a string");
	}
	const trimmed = value.trim();
	if (!trimmed || trimmed.length > MAX_PATTERN_LENGTH || hasControlChars(trimmed) || /\s/.test(trimmed)) {
		throw new errs.ValidationError("Invalid IP/CIDR pattern");
	}

	const parts = trimmed.split("/");
	if (parts.length > 2) {
		throw new errs.ValidationError("Invalid CIDR syntax");
	}

	const [rawIp, rawPrefix] = parts;
	const family = net.isIP(rawIp);
	if (family === 0) {
		throw new errs.ValidationError(`Invalid IP address: ${rawIp}`);
	}

	let canonicalIp = rawIp;
	if (family === 6) {
		// Node's WHATWG URL parser normalizes IPv6 literals to RFC 5952 canonical form.
		canonicalIp = new URL(`http://[${rawIp}]/`).hostname.slice(1, -1);
	}

	if (rawPrefix === undefined) {
		return canonicalIp;
	}

	if (!/^(?:0|[1-9][0-9]*)$/.test(rawPrefix)) {
		throw new errs.ValidationError(`Invalid CIDR prefix: /${rawPrefix}`);
	}
	const prefix = Number.parseInt(rawPrefix, 10);
	const maxPrefix = family === 4 ? 32 : 128;
	if (prefix < 0 || prefix > maxPrefix) {
		throw new errs.ValidationError(`CIDR prefix /${prefix} out of range for IPv${family}`);
	}
	return `${canonicalIp}/${prefix}`;
};

/**
 * Validates a PCRE regex against a bounded, ReDoS-safe subset:
 * - No control chars (NUL, CR, LF, etc.), max 512 chars
 * - Valid regex syntax
 * - No backreferences (\1..\9, \k), lookarounds ((?=...), (?!...), (?<=...), (?<!...)),
 *   PCRE verbs ((*...), (?R...)), or embedded modifiers/comments
 * - Max group depth 4, no nested quantifiers, no adjacent unbounded quantifiers,
 *   quantifier counts <= 1000.
 */
export const validateSafeRegex = (pattern, label = "pattern") => {
	if (typeof pattern !== "string") {
		throw new errs.ValidationError(`${label} must be a string`);
	}
	if (!pattern.length || pattern.length > MAX_PATTERN_LENGTH) {
		throw new errs.ValidationError(`${label} must be 1..${MAX_PATTERN_LENGTH} characters`);
	}
	if (hasControlChars(pattern)) {
		throw new errs.ValidationError(`${label} cannot contain control characters`);
	}

	try {
		// Sanity-check syntax before structural walk.
		new RegExp(pattern);
	} catch (err) {
		throw new errs.ValidationError(`Invalid ${label} regex: ${err.message}`);
	}

	const stack = [{ hasQuantifier: false, hasAlternation: false }];
	let inCharClass = false;
	let lastAtom = null; // null | "plain" | "unbounded"

	const readQuantifier = (idx) => {
		const ch = pattern[idx];
		if (ch === "*" || ch === "+") {
			const lazy = pattern[idx + 1] === "?" || pattern[idx + 1] === "+" ? 1 : 0;
			return { end: idx + 1 + lazy, unbounded: true };
		}
		if (ch === "?") {
			const lazy = pattern[idx + 1] === "?" || pattern[idx + 1] === "+" ? 1 : 0;
			return { end: idx + 1 + lazy, unbounded: false };
		}
		if (ch === "{") {
			const m = pattern.slice(idx).match(/^\{(\d+)(?:,(\d*))?\}([?+]?)/);
			if (!m) {
				return null;
			}
			const min = Number.parseInt(m[1], 10);
			const hasComma = m[2] !== undefined;
			const max = hasComma ? (m[2] === "" ? Number.POSITIVE_INFINITY : Number.parseInt(m[2], 10)) : min;
			if (min > MAX_QUANTIFIER_BOUND || (Number.isFinite(max) && (max > MAX_QUANTIFIER_BOUND || max < min))) {
				throw new errs.ValidationError(`${label} quantifier bound exceeds ${MAX_QUANTIFIER_BOUND}`);
			}
			return { end: idx + m[0].length, unbounded: max === Number.POSITIVE_INFINITY };
		}
		return null;
	};

	let i = 0;
	while (i < pattern.length) {
		const c = pattern[i];

		if (c === "\\") {
			const next = pattern[i + 1];
			if (next === undefined) {
				throw new errs.ValidationError(`${label} ends with dangling backslash`);
			}
			if (!inCharClass && (/[1-9]/.test(next) || next === "k")) {
				throw new errs.ValidationError(`${label} cannot use backreferences`);
			}
			i += 2;
			if (!inCharClass) {
				const q = readQuantifier(i);
				if (q) {
					if (q.unbounded && lastAtom === "unbounded") {
						throw new errs.ValidationError(`${label} cannot chain adjacent unbounded quantifiers`);
					}
					stack[stack.length - 1].hasQuantifier = true;
					lastAtom = q.unbounded ? "unbounded" : "plain";
					i = q.end;
				} else {
					lastAtom = "plain";
				}
			}
			continue;
		}

		if (inCharClass) {
			if (c === "]") {
				inCharClass = false;
				const q = readQuantifier(i + 1);
				if (q) {
					if (q.unbounded && lastAtom === "unbounded") {
						throw new errs.ValidationError(`${label} cannot chain adjacent unbounded quantifiers`);
					}
					stack[stack.length - 1].hasQuantifier = true;
					lastAtom = q.unbounded ? "unbounded" : "plain";
					i = q.end;
					continue;
				}
				lastAtom = "plain";
			}
			i++;
			continue;
		}

		if (c === "[") {
			inCharClass = true;
			i++;
			// Leading ^ or ] inside [...] is literal, not closing bracket.
			if (pattern[i] === "^") i++;
			if (pattern[i] === "]") i++;
			continue;
		}

		if (c === "(") {
			if (pattern[i + 1] === "*") {
				throw new errs.ValidationError(`${label} cannot use PCRE control verbs`);
			}
			if (pattern[i + 1] === "?") {
				if (pattern[i + 2] !== ":") {
					throw new errs.ValidationError(`${label} only supports plain or (?:...) groups`);
				}
				i += 3;
			} else {
				i += 1;
			}
			if (stack.length >= MAX_GROUP_DEPTH + 1) {
				throw new errs.ValidationError(`${label} group nesting exceeds ${MAX_GROUP_DEPTH}`);
			}
			stack.push({ hasQuantifier: false, hasAlternation: false });
			lastAtom = null;
			continue;
		}

		if (c === ")") {
			if (stack.length <= 1) {
				throw new errs.ValidationError(`${label} has unmatched ")"`);
			}
			const frame = stack.pop();
			i++;
			const q = readQuantifier(i);
			if (q) {
				if (frame.hasQuantifier || frame.hasAlternation) {
					throw new errs.ValidationError(`${label} cannot quantify a group containing quantifiers or alternations`);
				}
				if (q.unbounded && lastAtom === "unbounded") {
					throw new errs.ValidationError(`${label} cannot chain adjacent unbounded quantifiers`);
				}
				stack[stack.length - 1].hasQuantifier = true;
				lastAtom = q.unbounded ? "unbounded" : "plain";
				i = q.end;
			} else {
				if (frame.hasQuantifier) {
					stack[stack.length - 1].hasQuantifier = true;
				}
				lastAtom = "plain";
			}
			continue;
		}

		if (c === "|") {
			stack[stack.length - 1].hasAlternation = true;
			lastAtom = null;
			i++;
			continue;
		}

		if (c === "*" || c === "+" || c === "?" || c === "{") {
			const q = readQuantifier(i);
			if (q) {
				if (!lastAtom) {
					throw new errs.ValidationError(`${label} has quantifier without preceding atom`);
				}
				if (q.unbounded && lastAtom === "unbounded") {
					throw new errs.ValidationError(`${label} cannot chain adjacent unbounded quantifiers`);
				}
				stack[stack.length - 1].hasQuantifier = true;
				lastAtom = q.unbounded ? "unbounded" : "plain";
				i = q.end;
				continue;
			}
		}

		i++;
		const q = readQuantifier(i);
		if (q) {
			if (q.unbounded && lastAtom === "unbounded") {
				throw new errs.ValidationError(`${label} cannot chain adjacent unbounded quantifiers`);
			}
			stack[stack.length - 1].hasQuantifier = true;
			lastAtom = q.unbounded ? "unbounded" : "plain";
			i = q.end;
		} else {
			lastAtom = "plain";
		}
	}

	if (inCharClass || stack.length !== 1) {
		throw new errs.ValidationError(`${label} has unclosed group or character class`);
	}

	return pattern;
};

/**
 * Escapes a validated regex for a single double-quoted nginx map pattern ("~*...").
 * Tested with OpenResty ngx_conf_read_token: "\\" -> "\" and '\"' -> '"'.
 */
export const escapeNginxQuotedRegex = (pattern) => {
	return pattern.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
};

/**
 * Validates and normalizes an incoming block rule payload.
 */
export const validateBlockRuleInput = (input) => {
	const type = input.type;
	if (!RULE_TYPES.includes(type)) {
		throw new errs.ValidationError(`Unsupported block rule type: ${type}`);
	}

	const action = Number(input.action ?? 403);
	if (!RULE_ACTIONS.includes(action)) {
		throw new errs.ValidationError(`Unsupported block action: ${action}`);
	}

	let pattern;
	let refererPattern = "";

	if (type === "ip") {
		pattern = normalizeIpOrCidr(input.pattern);
		if (input.referer_pattern) {
			throw new errs.ValidationError("referer_pattern is only allowed for uri_referer rules");
		}
	} else {
		pattern = validateSafeRegex(input.pattern, "pattern");
		if (type === "uri_referer") {
			refererPattern = validateSafeRegex(input.referer_pattern, "referer_pattern");
		} else if (input.referer_pattern) {
			throw new errs.ValidationError("referer_pattern is only allowed for uri_referer rules");
		}
	}

	return {
		type,
		pattern,
		referer_pattern: refererPattern,
		action,
		enabled: input.enabled === undefined ? true : Boolean(input.enabled),
		note: typeof input.note === "string" ? input.note.trim() : "",
		approved_by: typeof input.approved_by === "string" ? input.approved_by.trim() : "",
		source: typeof input.source === "string" && input.source.trim() ? input.source.trim() : "ui",
	};
};

/**
 * Render-time revalidation of DB rows so stored values can never inject directives.
 */
export const assertBlockRuleRenderable = (rule) => {
	if (!Number.isInteger(rule?.id) || rule.id < 1) {
		throw new errs.ConfigurationError("Block rule has invalid id");
	}
	if (!RULE_ACTIONS.includes(Number(rule.action))) {
		throw new errs.ConfigurationError(`Block rule #${rule.id}: invalid action ${rule.action}`);
	}
	validateBlockRuleInput(rule);
};

/**
 * Renders /data/nginx/global/block-rules.conf.
 * Always defines $npm_blk, $npm_blk_static_rule, and $npm_blk_rule so custom
 * TASK-17 JSON log_format directives referencing $npm_blk_rule never fail nginx -t.
 */
export const renderBlockRulesConfig = (rules, { enabled = true } = {}) => {
	const header = "# Managed by Nginx Proxy Manager (block_rule). Do not edit by hand.\n";
	const acmeMaps = [
		"map $uri $npm_blk_acme {",
		"\tdefault 0;",
		'\t"~^/\\.well-known/acme-challenge/" 1;',
		"}",
		"map $uri $npm_blk_internal {",
		"\tvolatile;",
		"\tdefault 0;",
		'\t"~^/__npm_error/" 1;',
		"}",
	].join("\n");

	const active = enabled ? (rules || []).filter((r) => Boolean(r.enabled) && !r.is_deleted) : [];
	if (!active.length) {
		return [
			header,
			acmeMaps,
			'map "" $npm_blk { default ""; }',
			'map "" $npm_blk_static_rule { default ""; }',
			"",
		].join("\n");
	}

	for (const rule of active) {
		assertBlockRuleRenderable(rule);
	}

	const ipRules = active.filter((r) => r.type === "ip");
	const uaRules = active.filter((r) => r.type === "ua");
	const uriRules = active.filter((r) => r.type === "uri");
	const uriRefRules = active.filter((r) => r.type === "uri_referer");

	const blocks = [header, acmeMaps];

	if (ipRules.length) {
		blocks.push(
			[
				"geo $npm_blk_ip {",
				'\tdefault "";',
				...ipRules.map((r) => `\t${normalizeIpOrCidr(r.pattern)} "r${r.id}:${r.action}";`),
				"}",
			].join("\n"),
		);
	} else {
		blocks.push('map "" $npm_blk_ip { default ""; }');
	}

	if (uaRules.length) {
		blocks.push(
			[
				"map $http_user_agent $npm_blk_ua {",
				'\tdefault "";',
				...uaRules.map((r) => `\t"~*${escapeNginxQuotedRegex(r.pattern)}" "r${r.id}:${r.action}";`),
				"}",
			].join("\n"),
		);
	} else {
		blocks.push('map "" $npm_blk_ua { default ""; }');
	}

	if (uriRules.length) {
		blocks.push(
			[
				"map $request_uri $npm_blk_uri {",
				'\tdefault "";',
				...uriRules.map((r) => `\t"~*${escapeNginxQuotedRegex(r.pattern)}" "r${r.id}:${r.action}";`),
				"}",
			].join("\n"),
		);
	} else {
		blocks.push('map "" $npm_blk_uri { default ""; }');
	}

	if (uriRefRules.length) {
		const urVars = [];
		for (const r of uriRefRules) {
			const uVar = `$npm_blk_u_${r.id}`;
			const refVar = `$npm_blk_ref_${r.id}`;
			const urVar = `$npm_blk_ur_${r.id}`;
			urVars.push(urVar);
			blocks.push(
				[
					`map $request_uri ${uVar} {`,
					'\tdefault "";',
					`\t"~*${escapeNginxQuotedRegex(r.pattern)}" "1";`,
					"}",
					`map $http_referer ${refVar} {`,
					'\tdefault "";',
					`\t"~*${escapeNginxQuotedRegex(r.referer_pattern)}" "1";`,
					"}",
					`map "${uVar}${refVar}" ${urVar} {`,
					'\tdefault "";',
					`\t"11" "r${r.id}:${r.action}";`,
					"}",
				].join("\n"),
			);
		}
		blocks.push(
			[
				`map "${urVars.join("")}" $npm_blk_ur {`,
				'\tdefault "";',
				'\t"~^(r\\d+:\\d+)" $1;',
				"}",
			].join("\n"),
		);
	} else {
		blocks.push('map "" $npm_blk_ur { default ""; }');
	}

	const combined = '"$npm_blk_acme:$npm_blk_internal:$npm_blk_ip$npm_blk_ua$npm_blk_uri$npm_blk_ur"';
	blocks.push(
		[
			`map ${combined} $npm_blk {`,
			"\tvolatile;",
			'\tdefault "";',
			'\t"~^0:0:r(?<id>\\d+):(?<code>\\d+)" $code;',
			"}",
			'map "$npm_blk_acme:$npm_blk_ip$npm_blk_ua$npm_blk_uri$npm_blk_ur" $npm_blk_static_rule {',
			'\tdefault "";',
			'\t"~^0:(r\\d+):" $1;',
			"}",
			"",
		].join("\n"),
	);

	return blocks.join("\n\n");
};
