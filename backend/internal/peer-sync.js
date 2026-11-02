// Multi-NPM sync (orgoj fork): every NPM of a group exports its local hosts with the
// certificates and access lists they use; each member imports its peers' exports into
// its own DB as read-only rows marked with origin_peer_id + origin_id and renders them.
import fs from "node:fs";
import _ from "lodash";
import moment from "moment";
import errs from "../lib/error.js";
import withNginxLock from "../lib/nginx-lock.js";
import validator from "../lib/validator/index.js";
import { importer as logger } from "../logger.js";
import accessListModel from "../models/access_list.js";
import accessListAuthModel from "../models/access_list_auth.js";
import accessListClientModel from "../models/access_list_client.js";
import certificateModel from "../models/certificate.js";
import deadHostModel from "../models/dead_host.js";
import peerModel from "../models/peer.js";
import proxyHostModel from "../models/proxy_host.js";
import redirectionHostModel from "../models/redirection_host.js";
import userModel from "../models/user.js";
import internalHost from "./host.js";
import internalNginx from "./nginx.js";

const HOST_TYPES = [
	{ key: "proxy_hosts", model: proxyHostModel, type: "proxy_host", short: "proxy" },
	{ key: "redirection_hosts", model: redirectionHostModel, type: "redirection_host", short: "redirection" },
	{ key: "dead_hosts", model: deadHostModel, type: "dead_host", short: "dead" },
];
const EXPORT_KEYS = ["proxy_hosts", "redirection_hosts", "dead_hosts", "certificates", "access_lists"];
// Host columns that belong to each NPM and never travel; `id` travels as the source ID
const LOCAL_FIELDS = ["created_on", "modified_on", "owner_user_id", "is_deleted", "meta", "origin_peer_id", "origin_id"];
const FETCH_TIMEOUT = 30000;
const ACME_HTTP_FILE = "/data/nginx/acme_forward_http.conf";
const ACME_LOCATION_FILE = "/data/nginx/acme_forward.conf";
const PEER_FIELDS = ["id", "created_on", "modified_on", "name", "url", "email", "acme_address", "last_sync_on", "last_result"];

const certDir = (id) => `/data/custom_ssl/npm-${id}`;
const aclFile = (id) => `/data/access/${id}`;
const readFile = (file) => (fs.existsSync(file) ? fs.readFileSync(file, { encoding: "utf8" }) : null);
const sortedDomains = (names) => [...(names || [])].sort();
const sameFields = (row, fields) => _.isEqual(_.pick(row, Object.keys(fields)), fields);

const firstAdminId = async () => {
	const users = await userModel.query().where("is_deleted", 0).orderBy("id");
	const admin = users.find((u) => (u.roles || []).includes("admin"));
	if (!admin) {
		throw new Error("no admin user to own imported records");
	}
	return admin.id;
};

const internalPeerSync = {
	interval: null,
	running: false,

	/**
	 * GET /api/nginx/peer-export: every local record a peer needs, read straight from the DB
	 *
	 * @param {Access} access
	 */
	export: async (access) => {
		await access.can("peers:export");
		const out = Object.fromEntries(EXPORT_KEYS.map((k) => [k, []]));
		const certIds = new Set();
		const aclIds = new Set();

		for (const t of HOST_TYPES) {
			const rows = await t.model.query().where("is_deleted", 0).whereNull("origin_peer_id").orderBy("id");
			for (const row of rows) {
				out[t.key].push(_.omit(row, LOCAL_FIELDS));
				if (row.certificate_id > 0) certIds.add(row.certificate_id);
				if (row.access_list_id > 0) aclIds.add(row.access_list_id);
				for (const location of row.locations || []) {
					if (location.access_list_id > 0) aclIds.add(location.access_list_id);
				}
			}
		}

		const certs = await certificateModel
			.query()
			.where("is_deleted", 0)
			.whereNull("origin_peer_id")
			.whereIn("id", [...certIds]);
		for (const cert of certs) {
			let certificate = null;
			let key = null;
			if (cert.provider === "letsencrypt") {
				certificate = readFile(`/etc/letsencrypt/live/npm-${cert.id}/fullchain.pem`);
				key = readFile(`/etc/letsencrypt/live/npm-${cert.id}/privkey.pem`);
			} else {
				certificate = cert.meta.certificate;
				if (certificate && cert.meta.intermediate_certificate) {
					certificate = `${certificate}\n${cert.meta.intermediate_certificate}`;
				}
				key = cert.meta.certificate_key;
			}
			if (!certificate || !key) {
				// Not issued yet: the importer skips the hosts that use it
				continue;
			}
			out.certificates.push({
				id: cert.id,
				nice_name: cert.nice_name,
				domain_names: cert.domain_names,
				expires_on: moment(cert.expires_on).format("YYYY-MM-DD HH:mm:ss"),
				certificate,
				certificate_key: key,
			});
		}

		const lists = await accessListModel
			.query()
			.where("is_deleted", 0)
			.whereNull("origin_peer_id")
			.whereIn("id", [...aclIds])
			.withGraphFetched("[clients,items]");
		for (const list of lists) {
			out.access_lists.push({
				id: list.id,
				name: list.name,
				satisfy_any: list.satisfy_any,
				pass_auth: list.pass_auth,
				clients: list.clients.map((c) => ({ address: c.address, directive: c.directive })),
				items: list.items.map((i) => ({ username: i.username })),
				// hash lines as nginx reads them, never the stored passwords
				htpasswd: readFile(aclFile(list.id)) || "",
			});
		}
		return out;
	},

	/**
	 * Log in to the peer and fetch its export; anything but a complete export throws
	 *
	 * @param {Object} peer
	 */
	fetchExport: async (peer) => {
		const base = peer.url.replace(/\/+$/, "");
		const login = await fetch(`${base}/api/tokens`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ identity: peer.email, secret: peer.secret }),
			signal: AbortSignal.timeout(FETCH_TIMEOUT),
		});
		if (login.status !== 200) {
			throw new Error(`login HTTP ${login.status}`);
		}
		const { token } = await login.json();
		if (!token) {
			throw new Error("login returned no token");
		}
		const res = await fetch(`${base}/api/nginx/peer-export`, {
			headers: { Authorization: `Bearer ${token}` },
			signal: AbortSignal.timeout(FETCH_TIMEOUT),
		});
		if (res.status !== 200) {
			throw new Error(`export HTTP ${res.status}`);
		}
		const data = await res.json();
		for (const key of EXPORT_KEYS) {
			if (!Array.isArray(data?.[key])) {
				throw new Error(`export without ${key}`);
			}
		}
		return data;
	},

	/**
	 * One import run for one peer; the whole write, render and reload holds the nginx lock
	 *
	 * @param {Object} peer
	 */
	syncPeer: async (peer) => {
		let result;
		try {
			const data = await internalPeerSync.fetchExport(peer);
			result = await withNginxLock(() => internalPeerSync.applyExport(peer, data));
		} catch (err) {
			result = `error: ${err.message}`;
			logger.error(`Peer ${peer.name}: ${err.message}`);
		}
		await peerModel
			.query()
			.patch({ last_sync_on: moment().format("YYYY-MM-DD HH:mm:ss"), last_result: result })
			.where("id", peer.id);
		return result;
	},

	/**
	 * @param {Object} peer
	 * @param {Object} data  a complete export of that peer
	 * @returns {String}     the last_result line
	 */
	applyExport: async (peer, data) => {
		const ownerId = await firstAdminId();
		const stats = { imported: 0, updated: 0, unchanged: 0, deleted: 0, skipped: [], conflicts: [] };
		const certMap = {};
		const aclMap = {};
		const changedCerts = new Set();
		const changedAcls = new Set();
		const render = Object.fromEntries(HOST_TYPES.map((t) => [t.type, new Set()]));
		const removed = Object.fromEntries(HOST_TYPES.map((t) => [t.type, []]));

		// 1. certificates, stored as custom certificates so this member never renews them
		const localCerts = await certificateModel.query().where("origin_peer_id", peer.id);
		for (const c of data.certificates) {
			const fields = {
				provider: "other",
				nice_name: c.nice_name,
				domain_names: sortedDomains(c.domain_names),
				expires_on: c.expires_on,
				meta: { certificate: c.certificate, certificate_key: c.certificate_key },
			};
			let row = localCerts.find((r) => r.origin_id === c.id);
			if (!row) {
				row = await certificateModel
					.query()
					.insertAndFetch({ ...fields, owner_user_id: ownerId, origin_peer_id: peer.id, origin_id: c.id });
			} else if (sameFields(row, _.omit(fields, ["expires_on"]))) {
				certMap[c.id] = row.id;
				continue;
			} else {
				row = await certificateModel.query().patchAndFetchById(row.id, fields);
			}
			fs.mkdirSync(certDir(row.id), { recursive: true });
			fs.writeFileSync(`${certDir(row.id)}/fullchain.pem`, c.certificate);
			fs.writeFileSync(`${certDir(row.id)}/privkey.pem`, c.certificate_key);
			certMap[c.id] = row.id;
			changedCerts.add(row.id);
		}

		// 2. access lists, with the source's htpasswd hash lines
		const localAcls = await accessListModel
			.query()
			.where("origin_peer_id", peer.id)
			.withGraphFetched("[clients,items]");
		for (const a of data.access_lists) {
			const fields = { name: a.name, satisfy_any: a.satisfy_any, pass_auth: a.pass_auth };
			const clientsOf = (list) =>
				_.sortBy(
					list.map((c) => ({ address: c.address, directive: c.directive })),
					["address", "directive"],
				);
			const itemsOf = (list) => _.sortBy(list.map((i) => ({ username: i.username })), ["username"]);
			const clients = clientsOf(a.clients);
			const items = itemsOf(a.items);
			let row = localAcls.find((r) => r.origin_id === a.id);
			if (
				row &&
				sameFields(row, fields) &&
				_.isEqual(clientsOf(row.clients), clients) &&
				_.isEqual(itemsOf(row.items), items) &&
				readFile(aclFile(row.id)) === a.htpasswd
			) {
				aclMap[a.id] = row.id;
				continue;
			}
			if (!row) {
				row = await accessListModel
					.query()
					.insertAndFetch({ ...fields, owner_user_id: ownerId, origin_peer_id: peer.id, origin_id: a.id });
			} else {
				await accessListModel.query().patch(fields).where("id", row.id);
				await accessListClientModel.query().delete().where("access_list_id", row.id);
				await accessListAuthModel.query().delete().where("access_list_id", row.id);
			}
			for (const c of clients) {
				await accessListClientModel.query().insert({ ...c, access_list_id: row.id, meta: {} });
			}
			for (const i of items) {
				await accessListAuthModel.query().insert({ ...i, password: "", access_list_id: row.id, meta: {} });
			}
			fs.writeFileSync(aclFile(row.id), a.htpasswd, { encoding: "utf8" });
			aclMap[a.id] = row.id;
			changedAcls.add(row.id);
		}

		// 3. hosts, with certificate and access list IDs translated to the local ones
		let exportHosts = 0;
		let localHosts = 0;
		const seen = Object.fromEntries(HOST_TYPES.map((t) => [t.type, new Set()]));
		for (const t of HOST_TYPES) {
			const locals = await t.model.query().where("origin_peer_id", peer.id);
			localHosts += locals.length;
			exportHosts += data[t.key].length;
			for (const h of data[t.key]) {
				const label = `${t.short} ${h.id} (${(h.domain_names || []).join(", ")})`;
				const existing = locals.find((r) => r.origin_id === h.id);
				if (existing) {
					seen[t.type].add(existing.id);
				}
				const fields = _.omit(h, ["id"]);
				let missing = null;
				if (fields.certificate_id > 0) {
					fields.certificate_id = certMap[h.certificate_id] || 0;
					missing = fields.certificate_id ? missing : "certificate";
				}
				if (fields.access_list_id > 0) {
					fields.access_list_id = aclMap[h.access_list_id] || 0;
					missing = fields.access_list_id ? missing : "access list";
				}
				if (Array.isArray(fields.locations)) {
					fields.locations = fields.locations.map((l) => {
						if (!(l.access_list_id > 0)) return l;
						if (!aclMap[l.access_list_id]) missing = "access list";
						return { ...l, access_list_id: aclMap[l.access_list_id] || 0 };
					});
				}
				if (missing) {
					stats.skipped.push(`${label}: ${missing} not available`);
					continue;
				}

				let taken = null;
				for (const name of fields.domain_names || []) {
					const check = await internalHost.isHostnameTaken(name, t.short, existing?.id);
					if (check.is_taken) taken = name;
				}
				if (taken) {
					stats.conflicts.push(`${label}: ${taken} already in use`);
					continue;
				}

				try {
					let id;
					if (!existing) {
						const row = await t.model.query().insertAndFetch({
							...fields,
							owner_user_id: ownerId,
							origin_peer_id: peer.id,
							origin_id: h.id,
							meta: {},
						});
						id = row.id;
						seen[t.type].add(id);
						stats.imported++;
					} else if (!sameFields(existing, fields)) {
						await t.model.query().patch(fields).where("id", existing.id);
						id = existing.id;
						stats.updated++;
					} else if (
						changedCerts.has(existing.certificate_id) ||
						changedAcls.has(existing.access_list_id) ||
						(existing.locations || []).some((l) => changedAcls.has(l.access_list_id))
					) {
						id = existing.id;
						stats.unchanged++;
					} else {
						stats.unchanged++;
						continue;
					}
					if (fields.enabled === false || fields.enabled === 0) {
						removed[t.type].push({ id });
					} else {
						render[t.type].add(id);
					}
				} catch (err) {
					stats.skipped.push(`${label}: ${err.message}`);
				}
			}
		}

		// 4. deletes; an empty export never deletes (removing the peer is the deliberate way)
		const held = exportHosts === 0 && localHosts > 0;
		if (!held) {
			for (const t of HOST_TYPES) {
				const gone = await t.model.query().where("origin_peer_id", peer.id).whereNotIn("id", [...seen[t.type]]);
				for (const row of gone) {
					await t.model.query().deleteById(row.id);
					removed[t.type].push(row);
					stats.deleted++;
				}
			}
			stats.deleted += await internalPeerSync.deleteUnused(peer, Object.values(certMap), Object.values(aclMap));
		}

		// 5. one render, one test, one reload
		let offline = 0;
		const toRender = [];
		for (const t of HOST_TYPES) {
			for (const row of removed[t.type]) {
				await internalNginx.deleteConfig(t.type, row, true);
			}
			if (render[t.type].size) {
				const rows = await t.model
					.query()
					.whereIn("id", [...render[t.type]])
					.withGraphFetched(`[${t.model.defaultExpand.join(", ")}]`);
				for (const row of rows) {
					await internalNginx.deleteConfig(t.type, row, true);
					toRender.push({ t, row });
				}
			}
		}
		const changed = toRender.length + HOST_TYPES.reduce((n, t) => n + removed[t.type].length, 0);
		if (changed) {
			for (const { t, row } of toRender) {
				await internalNginx.generateConfig(t.type, row);
			}
			try {
				await internalNginx.test();
				for (const { t, row } of toRender) {
					await t.model
						.query()
						.patch({ meta: { ...row.meta, nginx_online: true, nginx_err: null } })
						.where("id", row.id);
				}
			} catch {
				// Isolate the bad host(s): NPM's configure marks each one online or offline (.err)
				for (const { t, row } of toRender) {
					await internalNginx.deleteConfig(t.type, row, true);
				}
				for (const { t, row } of toRender) {
					const meta = await internalNginx.configureUnlocked(t.model, t.type, row, true);
					if (!meta.nginx_online) offline++;
				}
			}
			await internalNginx.reload();
		}

		const parts = [
			`imported ${stats.imported}`,
			`updated ${stats.updated}`,
			`unchanged ${stats.unchanged}`,
			`deleted ${stats.deleted}`,
			`skipped ${stats.skipped.length}`,
			`conflicts ${stats.conflicts.length}`,
			`offline ${offline}`,
		];
		if (held) {
			parts.push("deletes held: export has no hosts");
		}
		const details = [...stats.skipped, ...stats.conflicts];
		return parts.join(", ") + (details.length ? `; ${details.join("; ")}` : "");
	},

	/**
	 * Delete this peer's certificates and access lists that are neither exported nor used
	 *
	 * @param {Object} peer
	 * @param {Array}  keepCerts  local IDs still exported
	 * @param {Array}  keepAcls
	 * @returns {Number}
	 */
	deleteUnused: async (peer, keepCerts, keepAcls) => {
		let deleted = 0;
		const certUsed = async (id) => {
			for (const t of HOST_TYPES) {
				if (await t.model.query().where("is_deleted", 0).where("certificate_id", id).first()) return true;
			}
			return false;
		};

		const certs = await certificateModel.query().where("origin_peer_id", peer.id).whereNotIn("id", keepCerts);
		for (const cert of certs) {
			if (await certUsed(cert.id)) continue;
			await certificateModel.query().deleteById(cert.id);
			fs.rmSync(certDir(cert.id), { recursive: true, force: true });
			deleted++;
		}

		const lists = await accessListModel.query().where("origin_peer_id", peer.id).whereNotIn("id", keepAcls);
		for (const list of lists) {
			const hosts = await proxyHostModel.query().where("is_deleted", 0);
			const inUse = hosts.some(
				(h) => h.access_list_id === list.id || (h.locations || []).some((l) => l.access_list_id === list.id),
			);
			if (inUse) continue;
			await accessListClientModel.query().delete().where("access_list_id", list.id);
			await accessListAuthModel.query().delete().where("access_list_id", list.id);
			await accessListModel.query().deleteById(list.id);
			fs.rmSync(aclFile(list.id), { force: true });
			deleted++;
		}
		return deleted;
	},

	/**
	 * Delete every record imported from this peer, hosts first
	 *
	 * @param {Object} peer
	 */
	deletePeerRecords: async (peer) => {
		let removed = 0;
		for (const t of HOST_TYPES) {
			for (const row of await t.model.query().where("origin_peer_id", peer.id)) {
				await t.model.query().deleteById(row.id);
				await internalNginx.deleteConfig(t.type, row, true);
				removed++;
			}
		}
		await internalPeerSync.deleteUnused(peer, [], []);
		if (removed) {
			await internalNginx.reload();
		}
	},

	/**
	 * Every 3 minutes (NPM_PEER_SYNC_SECONDS), one run per peer, one run at a time
	 */
	initTimer: () => {
		const seconds = Number.parseInt(process.env.NPM_PEER_SYNC_SECONDS, 10) || 180;
		logger.info(`Peer sync timer initialized (${seconds}s)`);
		internalPeerSync.renderAcmeForward().catch((err) => logger.error(`ACME forward: ${err.message}`));
		internalPeerSync.interval = setInterval(internalPeerSync.syncAll, seconds * 1000);
	},

	syncAll: async () => {
		if (internalPeerSync.running) {
			return;
		}
		internalPeerSync.running = true;
		try {
			for (const peer of await peerModel.query().orderBy("id")) {
				await internalPeerSync.syncPeer(peer);
			}
		} catch (err) {
			logger.error(err.message);
		} finally {
			internalPeerSync.running = false;
		}
	},

	/**
	 * The ACME HTTP-01 forward to all peers (letsencrypt-acme-challenge.conf), reloaded on change
	 */
	renderAcmeForward: () =>
		withNginxLock(async () => {
			const peers = (await peerModel.query().orderBy("id")).filter((p) => p.acme_address);
			const header = "# Rendered by NPM from the peer table (multi-NPM sync)\n";
			let http = header;
			let location = `${header}return 404;\n`;
			if (peers.length) {
				http += "upstream npm_acme_peers {\n";
				for (const p of peers) {
					http += `\tserver ${p.acme_address} max_fails=1 fail_timeout=60s;\n`;
				}
				http += "}\nlimit_req_zone $binary_remote_addr zone=acme_fwd:1m rate=10r/s;\n";
				location = `${header}if ($http_x_npm_acme_forwarded) {
	return 404;
}
limit_req zone=acme_fwd burst=20 nodelay;
proxy_set_header Host $host;
proxy_set_header X-NPM-ACME-Forwarded 1;
proxy_next_upstream error timeout http_404;
proxy_next_upstream_tries 0;
proxy_connect_timeout 2s;
proxy_read_timeout 5s;
proxy_pass http://npm_acme_peers;
`;
			}
			if (readFile(ACME_HTTP_FILE) === http && readFile(ACME_LOCATION_FILE) === location) {
				return;
			}
			fs.writeFileSync(ACME_HTTP_FILE, http, { encoding: "utf8" });
			fs.writeFileSync(ACME_LOCATION_FILE, location, { encoding: "utf8" });
			await internalNginx.reload();
		}),

	// Peers API (admin)

	getAll: async (access) => {
		await access.can("peers:manage");
		return peerModel.query().select(PEER_FIELDS).orderBy("id");
	},

	create: async (access, payload) => {
		await access.can("peers:manage");
		const data = await validator(
			{
				type: "object",
				additionalProperties: false,
				required: ["name", "url", "email", "secret"],
				properties: {
					name: { type: "string", minLength: 1, maxLength: 100 },
					url: { type: "string", pattern: "^https?://[^\\s/]+(/[^\\s]*)?$", maxLength: 255 },
					email: { type: "string", minLength: 1, maxLength: 255 },
					secret: { type: "string", minLength: 1, maxLength: 255 },
					acme_address: { type: "string", pattern: "^([A-Za-z0-9.-]+|\\[[0-9A-Fa-f:.]+\\]):[0-9]{1,5}$" },
				},
			},
			payload,
		);
		const row = await peerModel.query().insertAndFetch({ acme_address: "", ...data });
		await internalPeerSync.renderAcmeForward();
		return _.pick(row, PEER_FIELDS);
	},

	delete: async (access, id) => {
		await access.can("peers:manage");
		const peer = await peerModel.query().findById(id);
		if (!peer) {
			throw new errs.ItemNotFoundError(id);
		}
		await withNginxLock(() => internalPeerSync.deletePeerRecords(peer));
		await peerModel.query().deleteById(peer.id);
		await internalPeerSync.renderAcmeForward();
		return true;
	},
};

export default internalPeerSync;
