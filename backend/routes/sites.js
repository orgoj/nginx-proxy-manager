import express from "express";
import internalSite from "../internal/site.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import { debug, express as logger } from "../logger.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

// Sites for webmaster agents: a proxy host from the fixed site-template (orgoj fork)
router
	.route("/")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * GET /api/sites: the calling agent's own hosts
	 */
	.get(async (req, res, next) => {
		try {
			res.status(200).send(await internalSite.getAll(res.locals.access));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})

	/**
	 * POST /api/sites {domain_names, forward_host, forward_port}
	 */
	.post(async (req, res, next) => {
		req.setTimeout(900000); // certificate issuance
		try {
			res.status(201).send(await internalSite.create(res.locals.access, req.body));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

export default router;
