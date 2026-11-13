import crypto from "node:crypto";
import {
	MAX_ACTIVE_BANS,
	createTokenVerifier,
	deriveBanSource,
	formatDbUtcDateTime,
	normalizeSingleIp,
	parseDbUtcMs,
	sendLuaBanControl,
	validateBanInput,
	writeBanBackupFile,
} from "../lib/bans.js";
import errs from "../lib/error.js";
import { parseDatePeriod } from "../lib/helpers.js";
import { nginx as logger } from "../logger.js";
import banAgentTokenModel from "../models/ban_agent_token.js";
import ipBanModel from "../models/ip_ban.js";
import TokenModel from "../models/token.js";
import internalAuditLog from "./audit-log.js";

const REHYDRATE_POLL_MS = 5000;
const LABEL_RE = /^[a-zA-Z0-9._-]{1,64}$/;
const MAX_AGENT_TOKEN_MS = 366 * 24 * 60 * 60 * 1000;

let activeEpoch = 1;
let pollTimer = null;
let syncQueue = Promise.resolve();

const serializeBan = (row) => {
	const expMs = parseDbUtcMs(row.expires_on);
	return {
		id: row.id,
		created_on: row.created_on,
		modified_on: row.modified_on,
		expires_on: Number.isFinite(expMs) ? new Date(expMs).toISOString() : row.expires_on,
		ip: row.ip,
		action: row.action,
		reason: row.reason || "",
		source: row.source || "manual",
		meta: row.meta || {},
	};
};

const serializeAgentToken = (row) => {
	const expMs = parseDbUtcMs(row.expires_on);
	return {
		id: row.id,
		created_on: row.created_on,
		modified_on: row.modified_on,
		expires_on: Number.isFinite(expMs) ? new Date(expMs).toISOString() : row.expires_on,
		is_revoked: Boolean(row.is_revoked),
		jti: row.jti,
		label: row.label,
		created_by: row.created_by,
	};
};

const fetchActiveBans = async (nowMs = Date.now(), trx = null) => {
	const query = trx ? ipBanModel.query(trx) : ipBanModel.query();
	const rows = await query.where("is_deleted", 0).orderBy("id", "desc");
	const active = [];
	const expiredIds = [];
	for (const row of rows) {
		const expMs = parseDbUtcMs(row.expires_on);
		if (Number.isFinite(expMs) && expMs > nowMs) {
			active.push({ row, expires_ms: expMs });
		} else {
			expiredIds.push(row.id);
		}
	}
	if (expiredIds.length) {
		// Soft-delete expired entries and release active_ip uniqueness so DB and Lua stay aligned.
		const patchQuery = trx ? ipBanModel.query(trx) : ipBanModel.query();
		await patchQuery.whereIn("id", expiredIds).patch({ is_deleted: 1, active_ip: null });
	}
	return active;
};

const enqueueSyncTask = (fn) => {
	const run = syncQueue.then(() => fn());
	syncQueue = run.catch(() => {});
	return run;
};

const toBackupItems = (active) =>
	active.map(({ row, expires_ms }) => ({
		id: row.id,
		ip: row.ip,
		action: row.action,
		expires_ms,
	}));

const writeAndSyncAll = async (epoch) => {
	const nowMs = Date.now();
	const active = await fetchActiveBans(nowMs);
	if (active.length > MAX_ACTIVE_BANS) {
		throw new errs.InternalValidationError(
			`Active IP bans (${active.length}) exceed Lua sync limit (${MAX_ACTIVE_BANS})`,
		);
	}
	const backupItems = toBackupItems(active);
	writeBanBackupFile(backupItems);

	const luaBans = backupItems.map((b) => ({
		id: b.id,
		ip: b.ip,
		action: b.action,
		ttl: Math.max(1, Math.ceil((b.expires_ms - nowMs) / 1000)),
	}));
	return sendLuaBanControl("POST", "/internal/bans", {
		op: "sync",
		epoch,
		bans: luaBans,
	});
};

const internalIpBan = {
	syncOnStartup: async () => {
		activeEpoch = Date.now();
		await enqueueSyncTask(async () => {
			// Nginx may still be binding the Unix socket concurrently during s6 startup.
			for (let attempt = 0; attempt < 5; attempt++) {
				const res = await writeAndSyncAll(activeEpoch).catch((err) => {
					logger.warn(`IP ban initial Lua sync attempt ${attempt + 1} failed: ${err.message}`);
					return { available: false };
				});
				if (res?.available) {
					break;
				}
				await new Promise((r) => setTimeout(r, 1000));
			}
		});

		if (!pollTimer) {
			pollTimer = setInterval(() => {
				enqueueSyncTask(async () => {
					const ping = await sendLuaBanControl("GET", "/internal/bans").catch(() => null);
					if (ping?.available && ping.epoch !== activeEpoch) {
						logger.info(
							`Rehydrating IP bans into OpenResty after nginx restart (epoch ${ping.epoch} -> ${activeEpoch})`,
						);
						await writeAndSyncAll(activeEpoch);
					}
				}).catch((err) => {
					logger.warn(`IP ban rehydration check failed: ${err.message}`);
				});
			}, REHYDRATE_POLL_MS);
			pollTimer.unref();
		}
	},

	stopRehydrationLoop: () => {
		if (pollTimer) {
			clearInterval(pollTimer);
			pollTimer = null;
		}
	},

	getAll: async (access) => {
		await access.can("bans:list");
		const active = await fetchActiveBans();
		return active.map(({ row }) => serializeBan(row));
	},

	create: async (access, data) => {
		await access.can("bans:create");
		const validated = validateBanInput(data);
		const derivedSource = deriveBanSource(access);

		const saved = await enqueueSyncTask(async () => {
			const rowSaved = await ipBanModel.transaction(async (trx) => {
				const active = await fetchActiveBans(Date.now(), trx);
				const existing = active.find((b) => b.row.ip === validated.ip)?.row;
				if (existing) {
					return ipBanModel.query(trx).patchAndFetchById(existing.id, {
						active_ip: validated.ip,
						is_deleted: 0,
						action: validated.action,
						expires_on: validated.expires_on,
						reason: validated.reason,
						source: derivedSource,
						meta: existing.meta || {},
					});
				}

				if (active.length >= MAX_ACTIVE_BANS) {
					throw new errs.ValidationError(`Active IP ban limit (${MAX_ACTIVE_BANS}) reached`);
				}

				return ipBanModel.query(trx).insertAndFetch({
					ip: validated.ip,
					active_ip: validated.ip,
					action: validated.action,
					expires_on: validated.expires_on,
					reason: validated.reason,
					source: derivedSource,
					meta: {},
				});
			});

			const activeAfter = await fetchActiveBans();
			if (activeAfter.length > MAX_ACTIVE_BANS) {
				throw new errs.InternalValidationError(
					`Active IP bans (${activeAfter.length}) exceed Lua sync limit (${MAX_ACTIVE_BANS})`,
				);
			}
			writeBanBackupFile(toBackupItems(activeAfter));

			const liveEntry = activeAfter.find((b) => b.row.id === rowSaved.id && b.row.ip === rowSaved.ip);
			if (liveEntry) {
				await sendLuaBanControl("POST", "/internal/bans", {
					op: "set",
					id: rowSaved.id,
					ip: rowSaved.ip,
					action: rowSaved.action,
					ttl: Math.max(1, Math.ceil((liveEntry.expires_ms - Date.now()) / 1000)),
				});
			} else {
				await sendLuaBanControl("POST", "/internal/bans", {
					op: "del",
					ip: rowSaved.ip,
				});
			}

			return rowSaved;
		});

		await internalAuditLog.add(access, {
			action: "created",
			object_type: "ip-ban",
			object_id: saved.id,
			meta: {
				ip: saved.ip,
				action: saved.action,
				expires_on: saved.expires_on,
				source: saved.source,
			},
		});

		return serializeBan(saved);
	},

	delete: async (access, data) => {
		await access.can("bans:revoke");
		const targetIp = data?.id ? null : data?.ip ? normalizeSingleIp(data.ip) : null;

		const row = await enqueueSyncTask(async () => {
			const deleted = await ipBanModel.transaction(async (trx) => {
				await fetchActiveBans(Date.now(), trx);
				let found = null;
				if (data?.id) {
					found = await ipBanModel.query(trx).where("id", data.id).andWhere("is_deleted", 0).first();
				} else if (targetIp) {
					found = await ipBanModel.query(trx).where("ip", targetIp).andWhere("is_deleted", 0).first();
				}
				if (!found) {
					throw new errs.ItemNotFoundError(data?.id || data?.ip);
				}
				await ipBanModel.query(trx).where("id", found.id).patch({ is_deleted: 1, active_ip: null });
				return found;
			});

			const activeAfter = await fetchActiveBans();
			if (activeAfter.length > MAX_ACTIVE_BANS) {
				throw new errs.InternalValidationError(
					`Active IP bans (${activeAfter.length}) exceed Lua sync limit (${MAX_ACTIVE_BANS})`,
				);
			}
			writeBanBackupFile(toBackupItems(activeAfter));

			await sendLuaBanControl("POST", "/internal/bans", {
				op: "del",
				ip: deleted.ip,
			});

			return deleted;
		});

		await internalAuditLog.add(access, {
			action: "deleted",
			object_type: "ip-ban",
			object_id: row.id,
			meta: { ip: row.ip, reason: row.reason, source: row.source },
		});

		return true;
	},

	/**
	 * Issues a revocable, DB-persisted "ban-agent" JWT for external tools.
	 * Only admins may mint it; never accepts a client-chosen scope.
	 */
	mintAgentToken: async (access, data = {}) => {
		await access.can("block_rules:manage");

		const label = typeof data.label === "string" && data.label.trim() ? data.label.trim() : "ban-agent";
		if (!LABEL_RE.test(label)) {
			throw new errs.ValidationError("label must match [a-zA-Z0-9._-]{1,64}");
		}

		const expiryStr = typeof data.expiry === "string" && data.expiry.trim() ? data.expiry.trim() : "365d";
		const expiry = parseDatePeriod(expiryStr);
		if (expiry === null || expiry.valueOf() - Date.now() > MAX_AGENT_TOKEN_MS || expiry.valueOf() <= Date.now()) {
			throw new errs.ValidationError("expiry must be between 1m and 365d");
		}

		const jti = crypto.randomBytes(16).toString("hex");
		const Token = TokenModel();
		const signed = await Token.create({
			jti,
			iss: "api",
			scope: ["ban-agent"],
			attrs: {
				id: 0,
				service: "ban-agent",
				label,
			},
			expiresIn: expiryStr,
		});

		const createdBy = typeof access.token?.getUserId === "function" ? access.token.getUserId(0) || 0 : 0;
		const record = await banAgentTokenModel.query().insertAndFetch({
			jti,
			token_hash: createTokenVerifier(signed.token),
			label,
			expires_on: formatDbUtcDateTime(expiry.valueOf()),
			is_revoked: 0,
			created_by: createdBy,
			meta: { expiry: expiryStr },
		});

		await internalAuditLog.add(access, {
			action: "created",
			object_type: "ban-agent-token",
			object_id: record.id,
			meta: { label, jti, expiry: expiryStr },
		});

		return {
			id: record.id,
			jti: record.jti,
			token: signed.token,
			expires: expiry.toISOString(),
			scope: "ban-agent",
			label,
		};
	},

	listAgentTokens: async (access) => {
		await access.can("block_rules:manage");
		const rows = await banAgentTokenModel.query().orderBy("id", "desc");
		return rows.map((row) => serializeAgentToken(row));
	},

	revokeAgentToken: async (access, id) => {
		await access.can("block_rules:manage");
		const row = await banAgentTokenModel.query().where("id", id).first();
		if (!row) {
			throw new errs.ItemNotFoundError(id);
		}
		if (!row.is_revoked) {
			await banAgentTokenModel.query().where("id", row.id).patch({ is_revoked: 1 });
			await internalAuditLog.add(access, {
				action: "deleted",
				object_type: "ban-agent-token",
				object_id: row.id,
				meta: { label: row.label, jti: row.jti },
			});
		}
		return true;
	},
};

export default internalIpBan;
