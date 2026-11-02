import express from "express";
import internalPeerSync from "../internal/peer-sync.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import { debug, express as logger } from "../logger.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

// Peer NPMs this member imports from (orgoj fork, multi-NPM sync), admin only
router
	.route("/")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * GET /api/peers
	 */
	.get(async (req, res, next) => {
		try {
			res.status(200).send(await internalPeerSync.getAll(res.locals.access));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})

	/**
	 * POST /api/peers
	 */
	.post(async (req, res, next) => {
		try {
			res.status(201).send(await internalPeerSync.create(res.locals.access, req.body));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/:peer_id")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * DELETE /api/peers/123: the peer's imported records first, then the peer
	 */
	.delete(async (req, res, next) => {
		try {
			const id = Number.parseInt(req.params.peer_id, 10);
			res.status(200).send(await internalPeerSync.delete(res.locals.access, id));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

export default router;
