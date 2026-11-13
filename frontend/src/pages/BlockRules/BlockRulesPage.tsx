import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import { Button, Loading } from "src/components";
import { T } from "src/locale";
import { showDeleteConfirmModal } from "src/modals";
import {
	type BlockRule,
	type BlockRuleAction,
	type BlockRulePayload,
	type BlockRuleType,
	createBlockRule,
	deleteBlockRule,
	toggleBlockRule,
	updateBlockRule,
	useBlockRules,
} from "./api";

interface FormState {
	id: number | null;
	type: BlockRuleType;
	pattern: string;
	refererPattern: string;
	action: BlockRuleAction;
	enabled: boolean;
	note: string;
	approvedBy: string;
}

const emptyForm = (): FormState => ({
	id: null,
	type: "ua",
	pattern: "",
	refererPattern: "",
	action: 403,
	enabled: true,
	note: "",
	approvedBy: "",
});

const fromRule = (rule: BlockRule): FormState => ({
	id: rule.id,
	type: rule.type,
	pattern: rule.pattern,
	refererPattern: rule.refererPattern || "",
	action: rule.action,
	enabled: rule.enabled,
	note: rule.note || "",
	approvedBy: rule.approvedBy || "",
});

export default function BlockRulesPage() {
	const queryClient = useQueryClient();
	const rules = useBlockRules();
	const [form, setForm] = useState<FormState | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [saved, setSaved] = useState(false);
	const [busy, setBusy] = useState(false);

	const run = async (fn: () => Promise<void>) => {
		setBusy(true);
		setError(null);
		setSaved(false);
		try {
			await fn();
		} catch (err: any) {
			setError(err.message);
		}
		setBusy(false);
	};

	const save = () =>
		run(async () => {
			if (!form) return;
			const payload: BlockRulePayload = {
				type: form.type,
				pattern: form.pattern,
				refererPattern: form.type === "uri_referer" ? form.refererPattern : "",
				action: form.action,
				enabled: form.enabled,
				note: form.note,
				approvedBy: form.approvedBy,
			};
			if (form.id === null) {
				await createBlockRule(payload);
			} else {
				await updateBlockRule(form.id, payload);
			}
			setForm(null);
			setSaved(true);
			await queryClient.invalidateQueries({ queryKey: ["block-rules"] });
		});

	const toggle = (rule: BlockRule) =>
		run(async () => {
			await toggleBlockRule(rule.id, !rule.enabled);
			setSaved(true);
			await queryClient.invalidateQueries({ queryKey: ["block-rules"] });
		});

	const confirmDelete = (rule: BlockRule) =>
		showDeleteConfirmModal({
			title: <T id="action.delete" />,
			children: <T id="block-rules.delete-confirm" data={{ pattern: rule.pattern }} />,
			invalidations: [["block-rules"]],
			onConfirm: async () => {
				await deleteBlockRule(rule.id);
				if (form?.id === rule.id) {
					setForm(null);
				}
			},
		});

	const canSubmit =
		!!form &&
		form.pattern.trim().length > 0 &&
		(form.type !== "uri_referer" || form.refererPattern.trim().length > 0);

	return (
		<div className="card mt-4">
			<div className="card-status-top bg-red" />
			<div className="card-header d-flex align-items-center">
				<h2 className="mt-1 mb-0 me-auto">
					<T id="block-rules" />
				</h2>
				<Button size="sm" disabled={busy} onClick={() => setForm(emptyForm())}>
					<T id="action.add" />
				</Button>
			</div>
			<div className="card-body">
				<Alert variant="danger" show={!!error} onClose={() => setError(null)} dismissible>
					<pre className="mb-0" style={{ whiteSpace: "pre-wrap" }}>
						{error}
					</pre>
				</Alert>
				<Alert variant="success" show={saved} onClose={() => setSaved(false)} dismissible>
					<T id="block-rules.saved" />
				</Alert>
				{rules.isLoading ? (
					<Loading noLogo />
				) : rules.data?.length ? (
					<div className="table-responsive">
						<table className="table table-sm table-vcenter">
							<thead>
								<tr>
									<th>
										<T id="block-rules.type" />
									</th>
									<th>
										<T id="block-rules.pattern" />
									</th>
									<th>
										<T id="block-rules.action" />
									</th>
									<th>
										<T id="block-rules.approved-by" />
									</th>
									<th>
										<T id="block-rules.note" />
									</th>
									<th>
										<T id="column.status" />
									</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{rules.data.map((rule) => (
									<tr key={rule.id}>
										<td>
											<code>{rule.type}</code>
										</td>
										<td>
											<code>{rule.pattern}</code>
											{rule.type === "uri_referer" && rule.refererPattern ? (
												<div className="text-secondary small">
													Referer: <code>{rule.refererPattern}</code>
												</div>
											) : null}
										</td>
										<td>{rule.action}</td>
										<td>{rule.approvedBy || "-"}</td>
										<td>{rule.note || "-"}</td>
										<td>
											<span className={`badge ${rule.enabled ? "bg-green-lt" : "bg-secondary-lt"}`}>
												<T id={rule.enabled ? "enabled" : "disabled"} />
											</span>
										</td>
										<td className="text-end text-nowrap">
											<Button size="sm" variant="ghost" disabled={busy} onClick={() => toggle(rule)}>
												<T id={rule.enabled ? "action.disable" : "action.enable"} />
											</Button>
											<Button
												size="sm"
												variant="ghost"
												disabled={busy}
												onClick={() => setForm(fromRule(rule))}
											>
												<T id="action.edit" />
											</Button>
											<Button
												size="sm"
												variant="ghost"
												actionType="danger"
												disabled={busy}
												onClick={() => confirmDelete(rule)}
											>
												<T id="action.delete" />
											</Button>
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				) : (
					<p className="text-secondary">
						<T id="block-rules.empty" />
					</p>
				)}

				{form && (
					<div className="border-top pt-3 mt-3">
						<div className="row g-2 mb-2">
							<div className="col-md-3">
								<label className="form-label" htmlFor="blk-type">
									<T id="block-rules.type" />
								</label>
								<select
									id="blk-type"
									className="form-select"
									value={form.type}
									onChange={(e) => setForm({ ...form, type: e.target.value as BlockRuleType })}
								>
									<option value="ip">ip</option>
									<option value="ua">ua</option>
									<option value="uri">uri</option>
									<option value="uri_referer">uri_referer</option>
								</select>
							</div>
							<div className="col-md-3">
								<label className="form-label" htmlFor="blk-action">
									<T id="block-rules.action" />
								</label>
								<select
									id="blk-action"
									className="form-select"
									value={form.action}
									onChange={(e) => setForm({ ...form, action: Number(e.target.value) as BlockRuleAction })}
								>
									<option value={403}>403</option>
									<option value={404}>404</option>
									<option value={444}>444</option>
								</select>
							</div>
							<div className="col-md-3">
								<label className="form-label" htmlFor="blk-approved-by">
									<T id="block-rules.approved-by" />
								</label>
								<input
									id="blk-approved-by"
									className="form-control"
									value={form.approvedBy}
									onChange={(e) => setForm({ ...form, approvedBy: e.target.value })}
								/>
							</div>
							<div className="col-md-3 d-flex align-items-end">
								<label className="form-check mb-2">
									<input
										type="checkbox"
										className="form-check-input"
										checked={form.enabled}
										onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
									/>
									<span className="form-check-label">
										<T id="enabled" />
									</span>
								</label>
							</div>
						</div>
						<div className="mb-2">
							<label className="form-label" htmlFor="blk-pattern">
								<T id="block-rules.pattern" />
							</label>
							<input
								id="blk-pattern"
								className="form-control font-monospace"
								placeholder={form.type === "ip" ? "203.0.113.0/24" : "^/wp-login\\.php"}
								value={form.pattern}
								onChange={(e) => setForm({ ...form, pattern: e.target.value })}
							/>
						</div>
						{form.type === "uri_referer" && (
							<div className="mb-2">
								<label className="form-label" htmlFor="blk-referer">
									<T id="block-rules.referer-pattern" />
								</label>
								<input
									id="blk-referer"
									className="form-control font-monospace"
									placeholder="^https?://spam\\.example/"
									value={form.refererPattern}
									onChange={(e) => setForm({ ...form, refererPattern: e.target.value })}
								/>
							</div>
						)}
						<div className="mb-3">
							<label className="form-label" htmlFor="blk-note">
								<T id="block-rules.note" />
							</label>
							<input
								id="blk-note"
								className="form-control"
								value={form.note}
								onChange={(e) => setForm({ ...form, note: e.target.value })}
							/>
						</div>
						<div className="d-flex gap-2">
							<Button actionType="primary" isLoading={busy} disabled={busy || !canSubmit} onClick={save}>
								<T id="save" />
							</Button>
							<Button disabled={busy} onClick={() => setForm(null)}>
								<T id="cancel" />
							</Button>
						</div>
					</div>
				)}
			</div>
		</div>
	);
}
