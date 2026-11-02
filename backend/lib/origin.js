// Records imported from a peer NPM (origin_peer_id set) are read-only here: only the
// peer import writes them (orgoj fork, multi-NPM sync).
import accessListModel from "../models/access_list.js";
import certificateModel from "../models/certificate.js";
import peerModel from "../models/peer.js";
import errs from "./error.js";

/**
 * Throws when the row with this id was imported from a peer
 *
 * @param {Object} model
 * @param {Number} id
 */
const assertLocal = async (model, id) => {
	const row = await model.query().select("id", "origin_peer_id").findById(id);
	if (row?.origin_peer_id) {
		const peer = await peerModel.query().select("name").findById(row.origin_peer_id);
		throw new errs.ValidationError(`Managed by peer ${peer ? peer.name : row.origin_peer_id}`);
	}
};

/**
 * A local host must not use an imported certificate or access list: its source can delete them
 *
 * @param {Object} data  host create or update payload
 */
const assertLocalRefs = async (data) => {
	if (data.certificate_id > 0) {
		await assertLocal(certificateModel, data.certificate_id);
	}
	if (data.access_list_id > 0) {
		await assertLocal(accessListModel, data.access_list_id);
	}
	for (const location of data.locations || []) {
		if (location.access_list_id > 0) {
			await assertLocal(accessListModel, location.access_list_id);
		}
	}
};

export { assertLocal, assertLocalRefs };
