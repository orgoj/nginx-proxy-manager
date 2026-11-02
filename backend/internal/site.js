// Agent sites API (orgoj fork, multi-NPM sync): a webmaster agent creates a proxy host from
// the admin's fixed template, choosing only domains and a backend from an allowlist.
import net from "node:net";
import _ from "lodash";
import errs from "../lib/error.js";
import apiValidator from "../lib/validator/api.js";
import validator from "../lib/validator/index.js";
import certificateModel from "../models/certificate.js";
import proxyHostModel from "../models/proxy_host.js";
import settingModel from "../models/setting.js";
import TokenModel from "../models/token.js";
import { getValidationSchema } from "../schema/index.js";
import internalNginx from "./nginx.js";
import internalProxyHost from "./proxy-host.js";

const SITE_SETTINGS = ["site-template", "site-backend-allow"];
const AGENT_FIELDS = ["domain_names", "forward_host", "forward_port"];
const FORBIDDEN_PORTS = [81];
// Never a site backend, whatever the allowlist says: unspecified, loopback, link-local, IPv4-mapped
const FORBIDDEN_RANGES = [
	["0.0.0.0", 32, "ipv4"],
	["127.0.0.0", 8, "ipv4"],
	["169.254.0.0", 16, "ipv4"],
	["::", 128, "ipv6"],
	["::1", 128, "ipv6"],
	["fe80::", 10, "ipv6"],
	["::ffff:0:0", 96, "ipv6"],
];

const family = (ip) => (net.isIPv4(ip) ? "ipv4" : "ipv6");

// One BlockList per family: an IPv6 list with ::ffff:0:0/96 also matches every IPv4 address
const blockList = (ranges, fam) => {
	const list = new net.BlockList();
	for (const [address, prefix, f] of ranges) {
		if (f === fam) list.addSubnet(address, prefix, f);
	}
	return list;
};

// IP literal in its canonical form only (no leading zeros, compressed lowercase IPv6)
const isCanonicalIp = (ip) => {
	if (typeof ip !== "string" || !net.isIP(ip)) return false;
	const host = new URL(net.isIPv6(ip) ? `http://[${ip}]` : `http://${ip}`).hostname;
	return host.replace(/^\[|\]$/g, "") === ip;
};

const parseCidr = (cidr) => {
	const [address, prefixText, extra] = String(cidr).split("/");
	const prefix = Number(prefixText);
	if (extra !== undefined || !isCanonicalIp(address) || !/^[0-9]{1,3}$/.test(prefixText || "")) return null;
	if (prefix > (net.isIPv4(address) ? 32 : 128)) return null;
	return [address, prefix, family(address)];
};

const isForbidden = (ip) => blockList(FORBIDDEN_RANGES, family(ip)).check(ip, family(ip));

const portSchema = { type: "integer", minimum: 1, maximum: 65535 };

const internalSite = {
	/**
	 * Body validation for PUT /api/settings/site-template and /site-backend-allow
	 *
	 * @param   {String} id
	 * @param   {Object} body
	 * @returns {Object|null}  the settings payload, or null for any other setting
	 */
	validateSetting: async (id, body) => {
		if (!SITE_SETTINGS.includes(id)) {
			return null;
		}
		const { meta } = await validator(
			{
				type: "object",
				additionalProperties: false,
				required: ["meta"],
				properties: { meta: { type: "object" } },
			},
			body,
		);

		if (id === "site-template") {
			const agentKeys = Object.keys(meta).filter((k) => AGENT_FIELDS.includes(k));
			if (agentKeys.length) {
				throw new errs.ValidationError(`site-template must not set ${agentKeys.join(", ")}`);
			}
			await apiValidator(getValidationSchema("/nginx/proxy-hosts", "post"), {
				..._.cloneDeep(meta),
				domain_names: ["example.com"],
				forward_host: "192.0.2.1",
				forward_port: 8080,
			});
		} else {
			for (const [cidr, ports] of Object.entries(meta)) {
				const range = parseCidr(cidr);
				if (!range) {
					throw new errs.ValidationError(`site-backend-allow: invalid CIDR ${cidr}`);
				}
				await validator({ type: "array", items: portSchema }, ports);
				if (ports.some((p) => FORBIDDEN_PORTS.includes(p))) {
					throw new errs.ValidationError(`site-backend-allow: port 81 is never allowed (${cidr})`);
				}
				const own = blockList([range], range[2]);
				const forbidden = blockList(FORBIDDEN_RANGES, range[2]);
				const overlap = FORBIDDEN_RANGES.some(
					([address, , f]) => f === range[2] && (own.check(address, f) || forbidden.check(range[0], f)),
				);
				if (overlap) {
					throw new errs.ValidationError(`site-backend-allow: ${cidr} overlaps a forbidden range`);
				}
			}
		}
		return { meta };
	},

	/**
	 * POST /api/sites
	 *
	 * @param {Access} access
	 * @param {Object} body
	 */
	create: async (access, body) => {
		await access.can("sites:manage");
		const agentId = access.token.getUserId(0);
		const data = await validator(
			{
				type: "object",
				additionalProperties: false,
				required: AGENT_FIELDS,
				properties: {
					domain_names: {
						type: "array",
						minItems: 1,
						maxItems: 100,
						uniqueItems: true,
						items: { type: "string", pattern: "^[a-z0-9-]+(\\.[a-z0-9-]+)+$", maxLength: 253 },
					},
					forward_host: { type: "string" },
					forward_port: portSchema,
				},
			},
			body,
		);

		if (!isCanonicalIp(data.forward_host)) {
			throw new errs.ValidationError("forward_host must be an IP address in canonical form");
		}
		if (isForbidden(data.forward_host) || FORBIDDEN_PORTS.includes(data.forward_port)) {
			throw new errs.ValidationError(`Backend ${data.forward_host}:${data.forward_port} is never allowed`);
		}
		const allow = (await settingModel.query().findById("site-backend-allow"))?.meta || {};
		const allowed = Object.entries(allow).some(([cidr, ports]) => {
			const range = parseCidr(cidr);
			return (
				range &&
				range[2] === family(data.forward_host) &&
				ports.includes(data.forward_port) &&
				blockList([range], range[2]).check(data.forward_host, range[2])
			);
		});
		if (!allowed) {
			throw new errs.ValidationError(
				`Backend ${data.forward_host}:${data.forward_port} is not in site-backend-allow`,
			);
		}

		const template = (await settingModel.query().findById("site-template"))?.meta || {};
		if (_.isEmpty(template)) {
			throw new errs.ValidationError("site-template is not set");
		}
		const payload = await apiValidator(getValidationSchema("/nginx/proxy-hosts", "post"), {
			..._.cloneDeep(template),
			...data,
		});

		// NPM's own create, as the agent user, without the NPM permissions an agent token lacks
		const token = TokenModel();
		token.set("attrs", { id: agentId });
		token.set("scope", ["user"]);
		const agentAccess = { can: async () => ({ permission_visibility: "all" }), token };

		const lastHost = (await proxyHostModel.query().max("id as id").first())?.id || 0;
		const lastCert = (await certificateModel.query().max("id as id").first())?.id || 0;
		try {
			return await internalProxyHost.create(agentAccess, payload);
		} catch (err) {
			// All or nothing: NPM leaves the host row behind when issuance fails
			const sameDomains = (row) => _.isEqual([...row.domain_names].sort(), [...data.domain_names].sort());
			const hosts = (
				await proxyHostModel.query().where("id", ">", lastHost).where("owner_user_id", agentId)
			).filter(sameDomains);
			if (!hosts.length) {
				throw err;
			}
			for (const row of hosts) {
				await internalNginx.deleteConfig("proxy_host", row, true);
				await proxyHostModel.query().deleteById(row.id);
			}
			const certs = (
				await certificateModel.query().where("id", ">", lastCert).where("owner_user_id", agentId)
			).filter(sameDomains);
			for (const row of certs) {
				await certificateModel.query().deleteById(row.id);
			}
			const failed = new errs.ValidationError(`Site not created: ${err.message}`);
			failed.status = 422;
			throw failed;
		}
	},

	/**
	 * GET /api/sites: the hosts the calling agent created
	 *
	 * @param {Access} access
	 */
	getAll: async (access) => {
		await access.can("sites:manage");
		const rows = await proxyHostModel
			.query()
			.where("is_deleted", 0)
			.where("owner_user_id", access.token.getUserId(0))
			.withGraphFetched("certificate")
			.orderBy("id");
		return rows.map((row) => ({
			id: row.id,
			domain_names: row.domain_names,
			forward_host: row.forward_host,
			forward_port: row.forward_port,
			enabled: row.enabled,
			online: !!row.meta?.nginx_online,
			certificate_expires_on: row.certificate?.expires_on || null,
		}));
	},
};

export default internalSite;
