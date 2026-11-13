import { migrate as logger } from "../logger.js";

const migrateName = "ip_ban";

/**
 * Migrate: dynamic reload-free IP bans table (orgoj fork, TASK-32)
 *
 * @see http://knexjs.org/#Schema
 *
 * @param   {Object} knex
 * @returns {Promise}
 */
const up = (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);

	return knex.schema
		.createTable("ip_ban", (table) => {
			table.increments().primary();
			table.dateTime("created_on").notNull();
			table.dateTime("modified_on").notNull();
			table.dateTime("expires_on").notNull();
			table.tinyint("is_deleted").notNull().unsigned().defaultTo(0);
			table.string("ip", 64).notNull();
			table.string("active_ip", 64).nullable().unique();
			table.integer("action").notNull().unsigned().defaultTo(403);
			table.string("reason", 500).notNull().defaultTo("");
			table.string("source", 64).notNull().defaultTo("manual");
			table.json("meta").notNull();
			table.index(["is_deleted", "expires_on"]);
			table.index(["ip", "is_deleted"]);
		})
		.createTable("ban_agent_token", (table) => {
			table.increments().primary();
			table.dateTime("created_on").notNull();
			table.dateTime("modified_on").notNull();
			table.dateTime("expires_on").notNull();
			table.tinyint("is_revoked").notNull().unsigned().defaultTo(0);
			table.string("jti", 64).notNull().unique();
			table.string("token_hash", 128).notNull();
			table.string("label", 64).notNull();
			table.integer("created_by").notNull().unsigned().defaultTo(0);
			table.json("meta").notNull();
			table.index(["is_revoked", "expires_on"]);
		})
		.then(() => {
			logger.info(`[${migrateName}] ip_ban and ban_agent_token tables created`);
		});
};

/**
 * Undo Migrate
 *
 * @param   {Object} knex
 * @returns {Promise}
 */
const down = (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);

	return knex.schema
		.dropTableIfExists("ban_agent_token")
		.dropTableIfExists("ip_ban")
		.then(() => {
			logger.info(`[${migrateName}] ip_ban and ban_agent_token tables dropped`);
		});
};

export { up, down };
