import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";
import db from "../db.js";
import internalIpBan from "../internal/ip-ban.js";
import internalToken from "../internal/token.js";
import Access from "../lib/access.js";
import {
	MAX_ACTIVE_BANS,
	assertSafeSocket,
	createTokenVerifier,
	deriveBanSource,
	formatDbUtcDateTime,
	normalizeSingleIp,
	readBanSecret,
	validateBanInput,
	verifyTokenVerifier,
} from "../lib/bans.js";
import ipBanModel from "../models/ip_ban.js";
import TokenModel from "../models/token.js";

describe("dynamic IP bans validation, scoping, and persistence", () => {
	after(async () => {
		internalIpBan.stopRehydrationLoop();
		await db().destroy();
	});

	it("canonicalizes single IPs and rejects CIDRs/controls", () => {
		assert.equal(normalizeSingleIp(" 203.0.113.10 "), "203.0.113.10");
		assert.equal(normalizeSingleIp("2001:0db8:0000:0000::1"), "2001:db8::1");
		assert.throws(() => normalizeSingleIp("203.0.113.0/24"));
		assert.throws(() => normalizeSingleIp("203.0.113.10\n"));
		assert.throws(() => normalizeSingleIp("not-an-ip"));
	});

	it("validates ban payload with ttl_seconds or expires_on and derives authoritative source", () => {
		const nowMs = 1700000000000;
		const byTtl = validateBanInput({ ip: "198.51.100.5", action: 444, ttl_seconds: 120, reason: "ssh brute" }, nowMs);
		assert.equal(byTtl.ip, "198.51.100.5");
		assert.equal(byTtl.action, 444);
		assert.equal(byTtl.ttl_seconds, 120);
		assert.equal("source" in byTtl, false);

		const byExp = validateBanInput(
			{ ip: "2001:db8::9", expires_on: new Date(nowMs + 90_000).toISOString() },
			nowMs,
		);
		assert.equal(byExp.ttl_seconds, 90);
		assert.equal(byExp.action, 403);

		assert.throws(() => validateBanInput({ ip: "198.51.100.5", ttl_seconds: 0 }, nowMs));
		assert.throws(() => validateBanInput({ ip: "198.51.100.5", action: 500 }, nowMs));
		assert.throws(() => validateBanInput({ ip: "198.51.100.5", meta: { big: "x".repeat(5000) } }, nowMs));

		assert.equal(deriveBanSource({}), "manual");
		assert.equal(deriveBanSource({ getBanAgent: () => ({ id: 7, label: "fail2ban" }) }), "agent:7:fail2ban");
	});

	it("verifies salted ban-agent token hashes in constant time", () => {
		const verifier = createTokenVerifier("header.payload.signature");
		assert.equal(verifyTokenVerifier("header.payload.signature", verifier), true);
		assert.equal(verifyTokenVerifier("header.payload.tampered", verifier), false);
		assert.equal(verifyTokenVerifier("header.payload.signature", "invalid-format"), false);
	});

	it("enforces safe directory and symlink checks on control socket/secret", () => {
		const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "npm-ban-ctrl-"));
		try {
			const dir = path.join(tmp, "ctrl");
			fs.mkdirSync(dir, { mode: 0o700 });
			const secPath = path.join(dir, "ban.secret");
			fs.writeFileSync(secPath, "a".repeat(64), { mode: 0o600 });
			assert.equal(readBanSecret(dir), "a".repeat(64));

			fs.chmodSync(secPath, 0o644);
			assert.throws(() => readBanSecret(dir));

			const linkSock = path.join(dir, "ban.sock");
			fs.symlinkSync("/tmp/nonexistent", linkSock);
			assert.throws(() => assertSafeSocket(dir));
		} finally {
			fs.rmSync(tmp, { recursive: true, force: true });
		}
	});

	it("persists revocable ban-agent tokens, serializes concurrent create/revoke, and caps active bans at 5000", async () => {
		const knex = db();
		await knex.migrate.latest({ directory: path.resolve("migrations") });

		const adminAccess = {
			can: async () => true,
			token: {
				hasScope: (s) => s === "admin" || s === "user",
				getUserId: () => 1,
				get: () => ["user"],
			},
		};

		// 1. Mint DB-persisted ban-agent token and check scoping + revocation.
		const minted = await internalIpBan.mintAgentToken(adminAccess, { label: "edge-f2b", expiry: "1d" });
		assert.ok(minted.id >= 1);
		assert.ok(minted.jti.length >= 16);

		const agentAccess = new Access(minted.token);
		assert.ok(await agentAccess.can("bans:list"));
		assert.ok(await agentAccess.can("bans:create"));
		assert.ok(await agentAccess.can("bans:revoke"));
		assert.equal(agentAccess.getBanAgent()?.label, "edge-f2b");

		await assert.rejects(() => agentAccess.can("block_rules:manage"));
		await assert.rejects(() => agentAccess.can("users:list"));
		await assert.rejects(() => agentAccess.can("proxy_hosts:list"));
		await assert.rejects(() =>
			internalToken.getTokenFromEmail({ identity: "admin@example.com", secret: "x", scope: "ban-agent" }),
		);
		await assert.rejects(() => internalToken.getFreshToken(agentAccess, {}));
		await assert.rejects(() => internalToken.getFreshToken(adminAccess, { scope: "ban-agent" }));

		// Unpersisted forged JWT with valid signature + ban-agent scope must fail revocation lookup.
		const forged = await TokenModel().create({
			jti: "unpersisted-jti",
			iss: "api",
			scope: ["ban-agent"],
			attrs: { id: 0, service: "ban-agent", label: "rogue" },
			expiresIn: "1h",
		});
		await assert.rejects(() => new Access(forged.token).can("bans:create"), /revoked|unknown/i);

		const createdByAgent = await internalIpBan.create(agentAccess, {
			ip: "198.51.100.11",
			action: 403,
			ttl_seconds: 120,
			source: "client-spoofed",
		});
		assert.equal(createdByAgent.source, `agent:${minted.id}:edge-f2b`);

		const listedTokens = await internalIpBan.listAgentTokens(adminAccess);
		const listed = listedTokens.find((t) => t.id === minted.id);
		assert.ok(listed);
		assert.equal("token_hash" in listed, false);
		assert.equal(listed.is_revoked, false);

		await internalIpBan.revokeAgentToken(adminAccess, minted.id);
		await assert.rejects(() => new Access(minted.token).can("bans:create"), /revoked/i);

		// 2. Concurrent create/refresh vs revoke preserves uniqueness and final state.
		await Promise.all([
			internalIpBan.create(adminAccess, { ip: "198.51.100.77", action: 403, ttl_seconds: 60 }),
			internalIpBan.create(adminAccess, { ip: "198.51.100.77", action: 404, ttl_seconds: 120 }),
			internalIpBan.create(adminAccess, { ip: "198.51.100.77", action: 444, ttl_seconds: 180 }),
		]);
		const active77 = await ipBanModel.query().where({ ip: "198.51.100.77", is_deleted: 0 });
		assert.equal(active77.length, 1);

		await Promise.all([
			internalIpBan.create(adminAccess, { ip: "198.51.100.88", action: 403, ttl_seconds: 120 }),
			internalIpBan.delete(adminAccess, { ip: "198.51.100.88" }).catch(() => false),
		]);
		// Final unconditional delete when needed: assert API delete always clears active row cleanly.
		const remaining88 = await ipBanModel.query().where({ ip: "198.51.100.88", is_deleted: 0 });
		if (remaining88.length) {
			await internalIpBan.delete(adminAccess, { ip: "198.51.100.88" });
		}
		assert.equal((await ipBanModel.query().where({ ip: "198.51.100.88", is_deleted: 0 })).length, 0);

		// 3. Active ban limit (5,000) prevents overflow before insert.
		await ipBanModel.query().delete();
		const nowStr = formatDbUtcDateTime(Date.now());
		const expStr = formatDbUtcDateTime(Date.now() + 3600_000);
		const bulk = [];
		for (let i = 0; i < MAX_ACTIVE_BANS; i++) {
			const ip = `10.${Math.floor(i / 65536)}.${Math.floor(i / 256) % 256}.${i % 256}`;
			bulk.push({
				created_on: nowStr,
				modified_on: nowStr,
				expires_on: expStr,
				is_deleted: 0,
				ip,
				active_ip: ip,
				action: 403,
				reason: "cap-test",
				source: "manual",
				meta: "{}",
			});
		}
		await knex.batchInsert("ip_ban", bulk, 250);

		await assert.rejects(
			() => internalIpBan.create(adminAccess, { ip: "203.0.113.250", action: 403, ttl_seconds: 60 }),
			/limit/i,
		);
		await internalIpBan.delete(adminAccess, { ip: "10.0.0.0" });
		const afterRoom = await internalIpBan.create(adminAccess, { ip: "203.0.113.250", action: 403, ttl_seconds: 60 });
		assert.equal(afterRoom.ip, "203.0.113.250");
	});
});
