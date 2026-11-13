import express from "express";
import internalIpBan from "../../internal/ip-ban.js";
import jwtdecode from "../../lib/express/jwt-decode.js";
import apiValidator from "../../lib/validator/api.js";
import validator from "../../lib/validator/index.js";
import { debug, express as logger } from "../../logger.js";
import { getValidationSchema } from "../../schema/index.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

const parseIntId = async (rawId) => {
	const data = await validator(
		{
			required: ["id"],
			additionalProperties: false,
			properties: {
				id: {
					$ref: "common#/properties/id",
				},
			},
		},
		{ id: rawId },
	);
	return Number.parseInt(data.id, 10);
};

router
	.route("/")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			const rows = await internalIpBan.getAll(res.locals.access);
			res.status(200).send(rows);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.post(async (req, res, next) => {
		try {
			const payload = await apiValidator(getValidationSchema("/nginx/bans", "post"), req.body);
			const result = await internalIpBan.create(res.locals.access, payload);
			res.status(201).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/unban")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(async (req, res, next) => {
		try {
			const payload = await apiValidator(getValidationSchema("/nginx/bans/unban", "post"), req.body);
			const result = await internalIpBan.delete(res.locals.access, { ip: payload.ip });
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/agent-token")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(async (req, res, next) => {
		try {
			const payload = await apiValidator(getValidationSchema("/nginx/bans/agent-token", "post"), req.body || {});
			const result = await internalIpBan.mintAgentToken(res.locals.access, payload);
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/agent-tokens")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			const rows = await internalIpBan.listAgentTokens(res.locals.access);
			res.status(200).send(rows);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/agent-tokens/:token_id")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.delete(async (req, res, next) => {
		try {
			const id = await parseIntId(req.params.token_id);
			const result = await internalIpBan.revokeAgentToken(res.locals.access, id);
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/:ban_id")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.delete(async (req, res, next) => {
		try {
			const id = await parseIntId(req.params.ban_id);
			const result = await internalIpBan.delete(res.locals.access, { id });
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

export default router;
