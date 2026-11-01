import express from "express";
import internalCustomFile from "../internal/custom-file.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import { debug, express as logger } from "../logger.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

/**
 * GET /api/custom-files
 *
 * Lists the editable files per directory: {nginx: [...], logrotate: [...]}
 */
router
	.route("/")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			res.status(200).send(await internalCustomFile.getAll(res.locals.access));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * /api/custom-files/:dir/:name  (dir: nginx | logrotate, name: *.conf)
 */
router
	.route("/:dir/:name")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			res.status(200).send(await internalCustomFile.get(res.locals.access, req.params));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})

	/**
	 * PUT body {content}: create or replace the file
	 */
	.put(async (req, res, next) => {
		try {
			const result = await internalCustomFile.save(res.locals.access, {
				dir: req.params.dir,
				name: req.params.name,
				content: req.body?.content,
			});
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.delete(async (req, res, next) => {
		try {
			res.status(200).send(await internalCustomFile.delete(res.locals.access, req.params));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

export default router;
