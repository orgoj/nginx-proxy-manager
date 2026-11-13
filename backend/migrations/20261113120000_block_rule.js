import { migrate as logger } from "../logger.js";

const migrateName = "block_rule";

/**
 * Migrate: global block rules table (orgoj fork, TASK-31)
 *
 * @see http://knexjs.org/#Schema
 *
 * @param   {Object} knex
 * @returns {Promise}
 */
const up = (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);

	return knex.schema
		.createTable("block_rule", (table) => {
			table.increments().primary();
			table.dateTime("created_on").notNull();
			table.dateTime("modified_on").notNull();
			table.integer("owner_user_id").notNull().unsigned().defaultTo(0);
			table.tinyint("is_deleted").notNull().unsigned().defaultTo(0);
			table.string("type", 32).notNull();
			table.string("pattern", 512).notNull();
			table.string("referer_pattern", 512).notNull().defaultTo("");
			table.integer("action").notNull().unsigned().defaultTo(403);
			table.tinyint("enabled").notNull().unsigned().defaultTo(1);
			table.string("note", 500).notNull().defaultTo("");
			table.string("approved_by", 255).notNull().defaultTo("");
			table.string("source", 64).notNull().defaultTo("ui");
			table.json("meta").notNull();
		})
		.then(() => {
			logger.info(`[${migrateName}] block_rule Table created`);
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

	return knex.schema.dropTableIfExists("block_rule").then(() => {
		logger.info(`[${migrateName}] block_rule Table dropped`);
	});
};

export { up, down };
