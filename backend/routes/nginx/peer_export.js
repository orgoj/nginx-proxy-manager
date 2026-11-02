import express from "express";
import internalPeerSync from "../../internal/peer-sync.js";
import jwtdecode from "../../lib/express/jwt-decode.js";
import { debug, express as logger } from "../../logger.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

router
	.route("/")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * GET /api/nginx/peer-export
	 *
	 * Local hosts with their certificates and access lists, for peer NPMs only (orgoj fork)
	 */
	.get(async (req, res, next) => {
		try {
			res.status(200).send(await internalPeerSync.export(res.locals.access));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

export default router;
