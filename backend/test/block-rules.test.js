import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import {
	MAX_HIT_QUERY_TAGS,
	MAX_SOCKET_RESPONSE_BYTES,
	attachHitCounters,
	readLuaBanHits,
	sendLuaBanControl,
} from "../lib/bans.js";
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

	it("reads bounded active hit tags in batches, skips stale keys, and caps socket response bytes", async () => {
		const missing = path.join(os.tmpdir(), `npm-hits-missing-${process.pid}`);
		assert.deepEqual(await readLuaBanHits(["r1"], missing), {});
		assert.deepEqual(await readLuaBanHits([], missing), {});

		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "npm-hits-"));
		fs.chmodSync(dir, 0o700);
		const sockPath = path.join(dir, "ban.sock");
		const secret = "s".repeat(64);
		fs.writeFileSync(path.join(dir, "ban.secret"), `${secret}\n`, { mode: 0o600 });

		const requests = [];
		let mode = "normal";
		const srv = http.createServer((req, res) => {
			const chunks = [];
			req.on("data", (c) => chunks.push(c));
			req.on("end", () => {
				const raw = Buffer.concat(chunks).toString("utf8");
				const parsed = raw ? JSON.parse(raw) : {};
				requests.push({
					method: req.method,
					url: req.url,
					secret: req.headers["x-npm-ban-secret"],
					tags: parsed.tags || [],
				});
				if (mode === "oversize") {
					res.writeHead(200, { "content-type": "application/json" });
					res.end(`{"ok":true,"pad":"${"x".repeat(MAX_SOCKET_RESPONSE_BYTES + 4096)}"}`);
					return;
				}
				const hits = { stale_deleted_99: { count: 999, last_hit: 1700000999 } };
				for (const tag of parsed.tags || []) {
					if (tag === "r1") hits[tag] = { count: 12, last_hit: 1700000000 };
					if (tag === "ban5") hits[tag] = { count: 3, last_hit: 1700000100 };
					if (tag === "ban2504") hits[tag] = { count: 8, last_hit: 1700000200 };
				}
				res.writeHead(200, { "content-type": "application/json" });
				res.end(JSON.stringify({ ok: true, hits }));
			});
		});
		await new Promise((resolve) => srv.listen(sockPath, resolve));
		fs.chmodSync(sockPath, 0o600);
		try {
			// Build > MAX_HIT_QUERY_TAGS tags to verify chunking and stale key filtering
			const manyTags = ["r1", "r2", "ban5"];
			for (let i = 0; i < MAX_HIT_QUERY_TAGS * 2 + 502; i += 1) {
				manyTags.push(`ban${i + 10}`);
			}
			const hits = await readLuaBanHits(manyTags, dir);
			assert.equal(requests.length, 3);
			assert.equal(requests[0].method, "POST");
			assert.equal(requests[0].url, "/internal/hits");
			assert.equal(requests[0].secret, secret);
			assert.ok(requests.every((r) => r.tags.length <= MAX_HIT_QUERY_TAGS));
			assert.equal(hits.stale_deleted_99, undefined);

			const rules = attachHitCounters([{ id: 1 }, { id: 2 }], "r", hits);
			assert.equal(rules[0].hit_count, 12);
			assert.equal(rules[0].last_hit_on, "2023-11-14T22:13:20.000Z");
			assert.equal(rules[1].hit_count, 0);
			assert.equal(rules[1].last_hit_on, null);

			const ban = attachHitCounters({ id: 5 }, "ban", hits);
			assert.equal(ban.hit_count, 3);
			assert.equal(ban.last_hit_on, "2023-11-14T22:15:00.000Z");
			const lastBatchBan = attachHitCounters({ id: 2504 }, "ban", hits);
			assert.equal(lastBatchBan.hit_count, 8);

			mode = "oversize";
			await assert.rejects(
				() => sendLuaBanControl("POST", "/internal/hits", { tags: ["r1"] }, dir),
				/exceeded/,
			);
			assert.deepEqual(await readLuaBanHits(["r1"], dir), {});
		} finally {
			srv.closeAllConnections?.();
			await new Promise((resolve) => srv.close(resolve));
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
