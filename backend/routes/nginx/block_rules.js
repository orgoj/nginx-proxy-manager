import express from "express";
import internalBlockRule from "../../internal/block-rule.js";
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

const parseIdParam = async (rawId) => {
	const data = await validator(
		{
			required: ["rule_id"],
			additionalProperties: false,
			properties: {
				rule_id: {
					$ref: "common#/properties/id",
				},
			},
		},
		{ rule_id: rawId },
	);
	return Number.parseInt(data.rule_id, 10);
};

router
	.route("/")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			const rows = await internalBlockRule.getAll(res.locals.access);
			res.status(200).send(rows);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.post(async (req, res, next) => {
		try {
			const payload = await apiValidator(getValidationSchema("/nginx/block-rules", "post"), req.body);
			const result = await internalBlockRule.create(res.locals.access, payload);
			res.status(201).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/:rule_id")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			const id = await parseIdParam(req.params.rule_id);
			const row = await internalBlockRule.get(res.locals.access, { id });
			res.status(200).send(row);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.put(async (req, res, next) => {
		try {
			const id = await parseIdParam(req.params.rule_id);
			const payload = await apiValidator(getValidationSchema("/nginx/block-rules/{ruleID}", "put"), req.body);
			payload.id = id;
			const result = await internalBlockRule.update(res.locals.access, payload);
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.delete(async (req, res, next) => {
		try {
			const id = await parseIdParam(req.params.rule_id);
			const result = await internalBlockRule.delete(res.locals.access, { id });
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/:rule_id/enable")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(async (req, res, next) => {
		try {
			const id = await parseIdParam(req.params.rule_id);
			const result = await internalBlockRule.setEnabled(res.locals.access, { id }, true);
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/:rule_id/disable")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(async (req, res, next) => {
		try {
			const id = await parseIdParam(req.params.rule_id);
			const result = await internalBlockRule.setEnabled(res.locals.access, { id }, false);
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

export default router;
