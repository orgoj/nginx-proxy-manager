import { migrate as logger } from "../logger.js";

const migrateName = "proxy_host_cache";

/**
 * Migrate: per-host edge micro-cache and public static paths (orgoj fork)
 *
 * @see http://knexjs.org/#Schema
 *
 * @param   {Object} knex
 * @returns {Promise}
 */
const up = (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);

	return knex.schema
		.alterTable("proxy_host", (table) => {
			table.tinyint("edge_cache_enabled").notNullable().defaultTo(0);
			table.string("cache_public_paths", 255).notNullable().defaultTo("/static/");
		})
		.then(() => {
			logger.info(`[${migrateName}] proxy_host Table altered`);
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
		.alterTable("proxy_host", (table) => {
			table.dropColumn("edge_cache_enabled");
			table.dropColumn("cache_public_paths");
		})
		.then(() => {
			logger.info(`[${migrateName}] proxy_host Table altered`);
		});
};

export { up, down };
