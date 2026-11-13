import { randomBytes } from "node:crypto";
import fs from "node:fs";
import errs from "../lib/error.js";
import withNginxLock from "../lib/nginx-lock.js";
import { isBlockRulesEnabled, renderBlockRulesConfig, validateBlockRuleInput } from "../lib/block-rules.js";
import { attachHitCounters, readLuaBanHits } from "../lib/bans.js";
import { nginx as logger } from "../logger.js";
import blockRuleModel from "../models/block_rule.js";
import internalAuditLog from "./audit-log.js";
import internalNginx from "./nginx.js";

const GLOBAL_DIR = "/data/nginx/global";
const CONF_NAME = "block-rules.conf";
const CONF_PATH = `${GLOBAL_DIR}/${CONF_NAME}`;
const DEFAULT_DEBOUNCE_MS = 5000;

const omissions = () => ["is_deleted"];

const ensureDir = async () => {
	await fs.promises.mkdir(GLOBAL_DIR, { recursive: true, mode: 0o755 });
	const st = await fs.promises.lstat(GLOBAL_DIR);
	if (!st.isDirectory()) {
		throw new errs.ValidationError(`${GLOBAL_DIR} is not a directory`);
	}
};

const readConf = async () => {
	let handle;
	try {
		handle = await fs.promises.open(CONF_PATH, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
		const st = await handle.stat();
		if (!st.isFile()) {
			throw new errs.ValidationError(`${CONF_PATH} is not a regular file`);
		}
		return await handle.readFile({ encoding: "utf8" });
	} catch (err) {
		if (err.code === "ENOENT") {
			return null;
		}
		if (err.code === "ELOOP") {
			throw new errs.ValidationError(`${CONF_PATH} is a symlink`);
		}
		throw err;
	} finally {
		await handle?.close();
	}
};

const removeQuietly = async (path) => {
	await fs.promises.unlink(path).catch((err) => {
		if (err.code !== "ENOENT") throw err;
	});
};

const putConf = async (content) => {
	if (content === null) {
		await removeQuietly(CONF_PATH);
		return;
	}
	const tmp = `${GLOBAL_DIR}/.${CONF_NAME}.${randomBytes(6).toString("hex")}.tmp`;
	const handle = await fs.promises.open(tmp, "wx", 0o644);
	try {
		await handle.writeFile(content, { encoding: "utf8" });
		await handle.chmod(0o644);
		await handle.sync();
	} finally {
		await handle.close();
	}
	try {
		await fs.promises.rename(tmp, CONF_PATH);
	} catch (err) {
		await removeQuietly(tmp);
		throw err;
	}
};

const nginxError = (err) => {
	const lines = String(err?.message || err)
		.split("\n")
		.filter((line) => line.indexOf("/var/log/nginx/error.log") === -1);
	return new errs.ValidationError(lines.join("\n").trim() || "nginx configuration test failed");
};

const writeAndReload = () =>
	withNginxLock(async () => {
		await ensureDir();
		const previous = await readConf();
		const rows = await blockRuleModel.query().where("is_deleted", 0).orderBy("id", "asc");
		const content = renderBlockRulesConfig(rows, { enabled: isBlockRulesEnabled() });
		if (content === previous) {
			return;
		}
		await putConf(content);
		try {
			await internalNginx.reload();
		} catch (err) {
			await putConf(previous);
			await internalNginx.reload().catch((reloadErr) => {
				logger.error(`Reload after restoring ${CONF_PATH} failed: ${reloadErr.message}`);
			});
			throw nginxError(err);
		}
		logger.info(`Global block rules config applied: ${CONF_PATH}`);
	});

// Leading + trailing debounce: first change applies immediately; rapid bursts
// within DEFAULT_DEBOUNCE_MS coalesce into one trailing nginx -t + reload.
let lastSyncAt = 0;
let pendingTimer = null;
let pendingWaiters = [];
let inflightPromise = null;

const flushPending = () => {
	pendingTimer = null;
	const waiters = pendingWaiters;
	pendingWaiters = [];
	const run = writeAndReload().then(
		(res) => {
			lastSyncAt = Date.now();
			for (const w of waiters) w.resolve(res);
		},
		(err) => {
			lastSyncAt = Date.now();
			for (const w of waiters) w.reject(err);
		},
	);
	inflightPromise = run.finally(() => {
		inflightPromise = null;
		if (pendingWaiters.length && !pendingTimer) {
			scheduleSync();
		}
	});
};

const scheduleSync = () => {
	const debounceMs = Number.parseInt(process.env.BLOCK_RULES_DEBOUNCE_MS || "", 10);
	const windowMs = Number.isFinite(debounceMs) && debounceMs >= 0 ? debounceMs : DEFAULT_DEBOUNCE_MS;
	const waitMs = Math.max(0, lastSyncAt + windowMs - Date.now());
	pendingTimer = setTimeout(flushPending, waitMs);
};

const syncConfig = () => {
	const debounceMs = Number.parseInt(process.env.BLOCK_RULES_DEBOUNCE_MS || "", 10);
	const windowMs = Number.isFinite(debounceMs) && debounceMs >= 0 ? debounceMs : DEFAULT_DEBOUNCE_MS;
	const elapsed = Date.now() - lastSyncAt;

	if (!inflightPromise && !pendingTimer && elapsed >= windowMs) {
		return new Promise((resolve, reject) => {
			pendingWaiters.push({ resolve, reject });
			flushPending();
		});
	}

	return new Promise((resolve, reject) => {
		pendingWaiters.push({ resolve, reject });
		if (!inflightPromise && !pendingTimer) {
			scheduleSync();
		}
	});
};

const sanitizeRow = (row) => {
	if (!row) return row;
	const copy = { ...row };
	delete copy.is_deleted;
	return copy;
};

const internalBlockRule = {
	syncOnStartup: async () => {
		await withNginxLock(async () => {
			await ensureDir();
			const previous = await readConf();
			const rows = await blockRuleModel.query().where("is_deleted", 0).orderBy("id", "asc");
			const content = renderBlockRulesConfig(rows, { enabled: isBlockRulesEnabled() });
			if (content !== previous) {
				await putConf(content);
				await internalNginx.reload().catch(async (err) => {
					logger.error(`Global block rules startup reload failed, restoring previous config: ${err.message}`);
					await putConf(previous);
				});
			}
		});
	},

	getAll: async (access) => {
		await access.can("block_rules:manage");
		const rows = await blockRuleModel
			.query()
			.where("is_deleted", 0)
			.orderBy("id", "desc")
			.withGraphFetched("[owner]");
		const hits = await readLuaBanHits(rows.map((r) => `r${r.id}`));
		return attachHitCounters(rows.map(sanitizeRow), "r", hits);
	},

	get: async (access, { id }) => {
		await access.can("block_rules:manage");
		const row = await blockRuleModel
			.query()
			.where("is_deleted", 0)
			.andWhere("id", id)
			.withGraphFetched("[owner]")
			.first();
		if (!row) {
			throw new errs.ItemNotFoundError(id);
		}
		const hits = await readLuaBanHits([`r${row.id}`]);
		return attachHitCounters(sanitizeRow(row), "r", hits);
	},

	create: async (access, data) => {
		await access.can("block_rules:manage", data);
		const normalized = validateBlockRuleInput(data);
		const row = await blockRuleModel.query().insertAndFetch({
			...normalized,
			owner_user_id: access.token.getUserId(1),
			meta: data.meta || {},
		});

		try {
			await syncConfig();
		} catch (err) {
			await blockRuleModel.query().deleteById(row.id).catch(() => {});
			throw err;
		}

		await internalAuditLog.add(access, {
			action: "created",
			object_type: "block-rule",
			object_id: row.id,
			meta: sanitizeRow(row),
		});

		return internalBlockRule.get(access, { id: row.id });
	},

	update: async (access, data) => {
		await access.can("block_rules:manage", data);
		const existing = await blockRuleModel
			.query()
			.where("is_deleted", 0)
			.andWhere("id", data.id)
			.first();
		if (!existing) {
			throw new errs.ItemNotFoundError(data.id);
		}

		const merged = {
			type: data.type ?? existing.type,
			pattern: data.pattern ?? existing.pattern,
			referer_pattern:
				data.referer_pattern !== undefined ? data.referer_pattern : existing.referer_pattern,
			action: data.action ?? existing.action,
			enabled: data.enabled !== undefined ? data.enabled : existing.enabled,
			note: data.note !== undefined ? data.note : existing.note,
			approved_by: data.approved_by !== undefined ? data.approved_by : existing.approved_by,
			source: data.source ?? existing.source,
		};
		const normalized = validateBlockRuleInput(merged);

		await blockRuleModel
			.query()
			.where("id", existing.id)
			.patch({
				...normalized,
				meta: data.meta !== undefined ? data.meta : existing.meta,
			});

		try {
			await syncConfig();
		} catch (err) {
			await blockRuleModel
				.query()
				.where("id", existing.id)
				.patch({
					type: existing.type,
					pattern: existing.pattern,
					referer_pattern: existing.referer_pattern,
					action: existing.action,
					enabled: existing.enabled,
					note: existing.note,
					approved_by: existing.approved_by,
					source: existing.source,
					meta: existing.meta,
				})
				.catch(() => {});
			throw err;
		}

		const updated = await internalBlockRule.get(access, { id: existing.id });
		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "block-rule",
			object_id: existing.id,
			meta: updated,
		});
		return updated;
	},

	setEnabled: async (access, { id }, enabled) => {
		await access.can("block_rules:manage");
		const existing = await blockRuleModel.query().where("is_deleted", 0).andWhere("id", id).first();
		if (!existing) {
			throw new errs.ItemNotFoundError(id);
		}

		await blockRuleModel.query().where("id", id).patch({ enabled });
		try {
			await syncConfig();
		} catch (err) {
			await blockRuleModel.query().where("id", id).patch({ enabled: existing.enabled }).catch(() => {});
			throw err;
		}

		await internalAuditLog.add(access, {
			action: enabled ? "enabled" : "disabled",
			object_type: "block-rule",
			object_id: id,
			meta: { id, enabled },
		});
		return true;
	},

	delete: async (access, { id }) => {
		await access.can("block_rules:manage");
		const existing = await blockRuleModel.query().where("is_deleted", 0).andWhere("id", id).first();
		if (!existing) {
			throw new errs.ItemNotFoundError(id);
		}

		await blockRuleModel.query().where("id", id).patch({ is_deleted: 1 });
		try {
			await syncConfig();
		} catch (err) {
			await blockRuleModel.query().where("id", id).patch({ is_deleted: 0 }).catch(() => {});
			throw err;
		}

		await internalAuditLog.add(access, {
			action: "deleted",
			object_type: "block-rule",
			object_id: id,
			meta: omissions().reduce((acc, k) => {
				delete acc[k];
				return acc;
			}, { ...existing }),
		});
		return true;
	},
};

export default internalBlockRule;
