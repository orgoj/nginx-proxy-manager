import express from "express";
import { isCI } from "../lib/config.js";
import errs from "../lib/error.js";
import logRequest from "../lib/express/log-request.js";
import TokenModel from "../models/token.js";
import pjson from "../package.json" with { type: "json" };
import { isSetup } from "../setup.js";
import auditLogRoutes from "./audit-log.js";
import ciRoutes from "./ci.js";
import customFilesRoutes from "./custom-files.js";
import logsRoutes from "./logs.js";
import accessListsRoutes from "./nginx/access_lists.js";
import certificatesHostsRoutes from "./nginx/certificates.js";
import deadHostsRoutes from "./nginx/dead_hosts.js";
import proxyHostsRoutes from "./nginx/proxy_hosts.js";
import peerExportRoutes from "./nginx/peer_export.js";
import redirectionHostsRoutes from "./nginx/redirection_hosts.js";
import peersRoutes from "./peers.js";
import sitesRoutes from "./sites.js";
import streamsRoutes from "./nginx/streams.js";
import reportsRoutes from "./reports.js";
import schemaRoutes from "./schema.js";
import settingsRoutes from "./settings.js";
import tokensRoutes from "./tokens.js";
import usersRoutes from "./users.js";
import versionRoutes from "./version.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

router.use(logRequest);

// Tokens with scope `peer` or `site_agent` work only on their own endpoints (orgoj fork, multi-NPM sync)
const scopeRoutes = {
	peer: (req) => req.path === "/nginx/peer-export" && req.method === "GET",
	site_agent: (req) => req.path === "/sites" || req.path === "/sites/",
};
router.use(async (req, res, next) => {
	let scope = [];
	try {
		scope = res.locals.token ? (await TokenModel().load(res.locals.token)).scope || [] : [];
	} catch {
		// an invalid token fails in the route itself
	}
	for (const [name, allowed] of Object.entries(scopeRoutes)) {
		if (scope.includes(name) && !allowed(req) && !(req.path === "/tokens" && req.method === "GET")) {
			return next(new errs.PermissionError("Permission Denied"));
		}
	}
	next();
});

/**
 * Health Check
 * GET /api
 */
router.get("/", async (_, res /*, next*/) => {
	const version = pjson.version.split("-").shift().split(".");
	const setup = await isSetup();

	res.status(200).send({
		status: "OK",
		setup,
		version: {
			major: Number.parseInt(version.shift(), 10),
			minor: Number.parseInt(version.shift(), 10),
			revision: Number.parseInt(version.shift(), 10),
		},
	});
});

router.use("/schema", schemaRoutes);
router.use("/tokens", tokensRoutes);
router.use("/users", usersRoutes);
router.use("/audit-log", auditLogRoutes);
router.use("/logs", logsRoutes);
router.use("/reports", reportsRoutes);
router.use("/settings", settingsRoutes);
router.use("/version", versionRoutes);
router.use("/custom-files", customFilesRoutes);
router.use("/nginx/proxy-hosts", proxyHostsRoutes);
router.use("/nginx/redirection-hosts", redirectionHostsRoutes);
router.use("/nginx/dead-hosts", deadHostsRoutes);
router.use("/nginx/streams", streamsRoutes);
router.use("/nginx/access-lists", accessListsRoutes);
router.use("/nginx/certificates", certificatesHostsRoutes);
router.use("/nginx/peer-export", peerExportRoutes);
router.use("/peers", peersRoutes);
router.use("/sites", sitesRoutes);

// Only include CI routes if we're in a CI environment
if (isCI()) {
	router.use("/ci", ciRoutes);
}

/**
 * API 404 for all other routes
 *
 * ALL /api/*
 */
router.all(/(.+)/, (req, _, next) => {
	req.params.page = req.params["0"];
	next(new errs.ItemNotFoundError(req.params.page));
});

export default router;
