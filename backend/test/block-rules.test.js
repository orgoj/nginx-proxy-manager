import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
	assertBlockRuleRenderable,
	escapeNginxQuotedRegex,
	normalizeIpOrCidr,
	renderBlockRulesConfig,
	validateBlockRuleInput,
	validateSafeRegex,
} from "../lib/block-rules.js";

describe("block-rules validation and rendering", () => {
	it("normalizes IPv4 and IPv6 addresses and CIDRs", () => {
		assert.equal(normalizeIpOrCidr(" 203.0.113.5 "), "203.0.113.5");
		assert.equal(normalizeIpOrCidr("203.0.113.0/24"), "203.0.113.0/24");
		assert.equal(normalizeIpOrCidr("2001:0db8:0000:0000::1/64"), "2001:db8::1/64");
		assert.throws(() => normalizeIpOrCidr("203.0.113.1/33"));
		assert.throws(() => normalizeIpOrCidr("2001:db8::1/129"));
		assert.throws(() => normalizeIpOrCidr("203.0.113.1/01"));
		assert.throws(() => normalizeIpOrCidr("1.2.3.4; return 200;"));
	});

	it("accepts safe PCRE patterns and rejects ReDoS/control/injection constructs", () => {
		assert.equal(validateSafeRegex("(semrush|mj12bot)"), "(semrush|mj12bot)");
		assert.equal(validateSafeRegex("^/wp-login\\.php$"), "^/wp-login\\.php$");
		assert.equal(validateSafeRegex("(?:bot|crawler)/[0-9]{1,3}"), "(?:bot|crawler)/[0-9]{1,3}");

		for (const bad of [
			"",
			"foo\nbar",
			"foo\x00bar",
			"(a+)+",
			"(a|aa)+",
			".*.*",
			"(?=foo)bar",
			"(a)\\1",
			"(*FAIL)foo",
			"a{1001}",
			"(((((a)))))",
			"unclosed(",
		]) {
			assert.throws(() => validateSafeRegex(bad), `expected reject for ${JSON.stringify(bad)}`);
		}
	});

	it("escapes backslashes and quotes for nginx double-quoted regex strings", () => {
		assert.equal(escapeNginxQuotedRegex('evil\\.bot"test'), 'evil\\\\.bot\\"test');
	});

	it("validates full rule payloads and revalidates at render time", () => {
		const valid = validateBlockRuleInput({
			type: "uri_referer",
			pattern: "^/shop/",
			referer_pattern: "^https?://spam\\.example/",
			action: 444,
			enabled: true,
			note: "spammer",
			approved_by: "michael",
		});
		assert.equal(valid.type, "uri_referer");
		assert.equal(valid.action, 444);

		assert.throws(() =>
			validateBlockRuleInput({
				type: "ua",
				pattern: "bot",
				referer_pattern: "unexpected",
			}),
		);
		assert.throws(() =>
			validateBlockRuleInput({
				type: "ip",
				pattern: "198.51.100.1",
				action: 500,
			}),
		);
		assert.throws(() =>
			assertBlockRuleRenderable({
				id: 1,
				type: "ua",
				pattern: "bad\nline",
				action: 403,
			}),
		);
	});

	it("renders empty no-op config with $npm_blk_static_rule when disabled or empty", () => {
		const emptyCfg = renderBlockRulesConfig([], { enabled: true });
		assert.match(emptyCfg, /map "" \$npm_blk_static_rule \{ default ""; \}/);
		assert.match(emptyCfg, /map "" \$npm_blk \{ default ""; \}/);
		assert.doesNotMatch(emptyCfg, /map .* \$npm_blk_rule/);

		const offCfg = renderBlockRulesConfig(
			[{ id: 1, type: "ua", pattern: "bot", referer_pattern: "", action: 403, enabled: true, is_deleted: false }],
			{ enabled: false },
		);
		assert.doesNotMatch(offCfg, /bot/);
		assert.match(offCfg, /map "" \$npm_blk_static_rule \{ default ""; \}/);
	});

	it("renders ip > ua > uri > uri_referer with ACME and internal error exemptions", () => {
		const cfg = renderBlockRulesConfig(
			[
				{ id: 1, type: "ip", pattern: "203.0.113.0/24", referer_pattern: "", action: 444, enabled: true, is_deleted: false },
				{ id: 2, type: "ua", pattern: "evil\\.bot", referer_pattern: "", action: 403, enabled: true, is_deleted: false },
				{ id: 3, type: "uri", pattern: "^/wp-login\\.php", referer_pattern: "", action: 404, enabled: true, is_deleted: false },
				{
					id: 4,
					type: "uri_referer",
					pattern: "^/checkout",
					referer_pattern: "^https?://spam\\.test/",
					action: 403,
					enabled: true,
					is_deleted: false,
				},
				{ id: 5, type: "ua", pattern: "disabled-bot", referer_pattern: "", action: 403, enabled: false, is_deleted: false },
			],
			{ enabled: true },
		);
		assert.match(cfg, /geo \$npm_blk_ip/);
		assert.match(cfg, /203\.0\.113\.0\/24 "r1:444";/);
		assert.match(cfg, /"~\*evil\\\\\.bot" "r2:403";/);
		assert.match(cfg, /"~\*\^\/wp-login\\\\\.php" "r3:404";/);
		assert.match(cfg, /map \$request_uri \$npm_blk_u_4/);
		assert.match(cfg, /map \$http_referer \$npm_blk_ref_4/);
		assert.match(cfg, /"\$npm_blk_acme:\$npm_blk_internal:\$npm_blk_ip\$npm_blk_ua\$npm_blk_uri\$npm_blk_ur"/);
		assert.match(cfg, /"~\^\/\\\.well-known\/acme-challenge\/" 1;/);
		assert.match(cfg, /"~\^\/__npm_error\/" 1;/);
		assert.doesNotMatch(cfg, /disabled-bot/);
	});
});
