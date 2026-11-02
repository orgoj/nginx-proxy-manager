// Template variables for the per-host proxy cache (templates/_assets.conf).
// Fallback TTLs come from env vars, so all NPMs configured alike behave alike;
// upstream Cache-Control/Expires still win over them.

import { createHash } from "node:crypto";
import { nginx as logger } from "../logger.js";

const TTL_PATTERN = /^[1-9][0-9]*(ms|s|m|h|d)$/;
const PUBLIC_PATH_PATTERN = /^\/[A-Za-z0-9._~-]+(\/[A-Za-z0-9._~-]+)*\/$/;

const TTL_DEFAULTS = {
	NPM_CACHE_EDGE_VALID_200: "2s",
	NPM_CACHE_EDGE_VALID_301_302: "2m",
	NPM_CACHE_EDGE_VALID_404: "5m",
	NPM_CACHE_ASSET_VALID_200: "30m",
	NPM_CACHE_ASSET_VALID_404: "1m",
};

const ttl = (name) => {
	const value = (process.env[name] || "").trim();
	if (value === "") {
		return TTL_DEFAULTS[name];
	}
	if (!TTL_PATTERN.test(value)) {
		logger.warn(`${name}="${value}" is not an nginx time like 2s or 30m, using ${TTL_DEFAULTS[name]}`);
		return TTL_DEFAULTS[name];
	}
	return value;
};

/**
 * Space separated prefixes like "/static/ /media/" -> regex alternation for nginx.
 * Invalid entries (only possible from data that bypassed the API schema) are dropped.
 *
 * @param   {string} paths
 * @returns {string}
 */
const publicPathsRegex = (paths) => {
	return (paths || "")
		.split(/\s+/)
		.filter((path) => {
			if (path === "") {
				return false;
			}
			if (!PUBLIC_PATH_PATTERN.test(path)) {
				logger.warn(`Ignoring invalid cache public path "${path}"`);
				return false;
			}
			return true;
		})
		.map((path) => path.replace(/\./g, "\\."))
		.join("|");
};

const isOn = (value) => value === true || value === 1;

// Fields that change what a host serves or caches (a custom location's forward path is part
// of its locations[].forward_host). Their hash is part of the cache key,
// so any change of them (even two saves within one second) starts with an empty cache,
// while a plain regeneration keeps the entries.
const KEY_FIELDS = [
	"domain_names",
	"forward_scheme",
	"forward_host",
	"forward_port",
	"locations",
	"advanced_config",
	"access_list_id",
	"caching_enabled",
	"edge_cache_enabled",
	"cache_public_paths",
];

const cacheKeyVersion = (host) => {
	const relevant = KEY_FIELDS.map((field) => (typeof host[field] === "undefined" ? null : host[field]));
	return createHash("sha256").update(JSON.stringify(relevant)).digest("hex").slice(0, 12);
};

/**
 * @param   {Object} host  proxy host row
 * @returns {Object}       variables merged into the template data
 */
const templateVars = (host) => {
	return {
		cache_enabled: isOn(host.caching_enabled) || isOn(host.edge_cache_enabled),
		cache_edge: isOn(host.edge_cache_enabled),
		cache_public_regex: publicPathsRegex(host.cache_public_paths),
		cache_key_version: cacheKeyVersion(host),
		cache_edge_valid_200: ttl("NPM_CACHE_EDGE_VALID_200"),
		cache_edge_valid_301_302: ttl("NPM_CACHE_EDGE_VALID_301_302"),
		cache_edge_valid_404: ttl("NPM_CACHE_EDGE_VALID_404"),
		cache_asset_valid_200: ttl("NPM_CACHE_ASSET_VALID_200"),
		cache_asset_valid_404: ttl("NPM_CACHE_ASSET_VALID_404"),
	};
};

export { PUBLIC_PATH_PATTERN, publicPathsRegex, templateVars };
