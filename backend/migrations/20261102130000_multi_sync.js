import fs from "node:fs";
import { migrate as logger } from "../logger.js";

const migrateName = "multi_sync";

// Tables whose rows can be imported from a peer (orgoj fork, multi-NPM sync)
const originTables = ["proxy_host", "redirection_host", "dead_host", "certificate", "access_list"];
const siteSettings = [
	{ id: "site-template", name: "Site Template", description: "Proxy host template for POST /api/sites" },
	{ id: "site-backend-allow", name: "Site Backends", description: "Backends allowed for POST /api/sites" },
];

/**
 * Migrate: peer table, origin columns, agent site settings
 *
 * @param   {Object} knex
 * @returns {Promise}
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);

	await knex.schema.createTable("peer", (table) => {
		table.increments().primary();
		table.dateTime("created_on").notNull();
		table.dateTime("modified_on").notNull();
		table.string("name", 100).notNull();
		table.string("url", 255).notNull();
		table.string("email", 255).notNull();
		table.string("secret", 255).notNull();
		table.string("acme_address", 255).notNull().defaultTo("");
		table.dateTime("last_sync_on").nullable();
		table.text("last_result").nullable();
	});

	for (const name of originTables) {
		await knex.schema.alterTable(name, (table) => {
			table.integer("origin_peer_id").unsigned().nullable().references("id").inTable("peer").onDelete("RESTRICT");
			table.integer("origin_id").unsigned().nullable();
			table.unique(["origin_peer_id", "origin_id"]);
		});
	}

	for (const s of siteSettings) {
		await knex("setting").insert({ ...s, value: "", meta: "{}" });
	}

	logger.info(`[${migrateName}] peer table, origin columns and site settings added`);
};

/**
 * Undo Migrate
 *
 * @param   {Object} knex
 * @returns {Promise}
 */
const down = async (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);

	await knex("setting")
		.whereIn(
			"id",
			siteSettings.map((s) => s.id),
		)
		.delete();

	// Imported rows only exist through a peer, without it they are dangling copies
	for (const name of ["proxy_host", "redirection_host", "dead_host"]) {
		for (const row of await knex(name).select("id").whereNotNull("origin_peer_id")) {
			fs.rmSync(`/data/nginx/${name}/${row.id}.conf`, { force: true });
			fs.rmSync(`/data/nginx/${name}/${row.id}.conf.err`, { force: true });
		}
	}
	const importedLists = knex("access_list").select("id").whereNotNull("origin_peer_id");
	await knex("access_list_auth").whereIn("access_list_id", importedLists).delete();
	await knex("access_list_client").whereIn("access_list_id", importedLists).delete();
	for (const name of originTables) {
		await knex(name).whereNotNull("origin_peer_id").delete();
		await knex.schema.alterTable(name, (table) => {
			table.dropUnique(["origin_peer_id", "origin_id"]);
			table.dropForeign(["origin_peer_id"]);
			table.dropColumn("origin_peer_id");
			table.dropColumn("origin_id");
		});
	}

	await knex.schema.dropTable("peer");
	logger.info(`[${migrateName}] multi-sync schema removed`);
};

export { up, down };
