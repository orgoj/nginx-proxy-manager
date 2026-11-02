// Objection Docs:
// http://vincit.github.io/objection.js/

import { Model } from "objection";
import db from "../db.js";
import now from "./now_helper.js";

Model.knex(db());

// Another NPM of the sync group whose local records this NPM imports (orgoj fork)
class Peer extends Model {
	$beforeInsert() {
		this.created_on = now();
		this.modified_on = now();
	}

	$beforeUpdate() {
		this.modified_on = now();
	}

	static get name() {
		return "Peer";
	}

	static get tableName() {
		return "peer";
	}
}

export default Peer;
