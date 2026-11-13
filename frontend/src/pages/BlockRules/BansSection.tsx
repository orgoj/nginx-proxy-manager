import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import { Button, Loading } from "src/components";
import { T } from "src/locale";
import {
	type BlockRuleAction,
	createIpBan,
	mintBanAgentToken,
	revokeBanAgentToken,
	revokeIpBan,
	useBanAgentTokens,
	useIpBans,
} from "./api";

interface BanFormState {
	ip: string;
	action: BlockRuleAction;
	ttlSeconds: number;
	reason: string;
}

const emptyBanForm = (): BanFormState => ({
	ip: "",
	action: 403,
	ttlSeconds: 3600,
	reason: "",
});

export default function BansSection() {
	const queryClient = useQueryClient();
	const bans = useIpBans();
	const agentTokens = useBanAgentTokens();
	const [form, setForm] = useState<BanFormState | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [saved, setSaved] = useState(false);
	const [agentToken, setAgentToken] = useState<string | null>(null);
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
			await createIpBan({
				ip: form.ip,
				action: form.action,
				ttlSeconds: form.ttlSeconds,
				reason: form.reason,
			});
			setForm(null);
			setSaved(true);
			await queryClient.invalidateQueries({ queryKey: ["ip-bans"] });
		});

	const unban = (id: number) =>
		run(async () => {
			await revokeIpBan(id);
			setSaved(true);
			await queryClient.invalidateQueries({ queryKey: ["ip-bans"] });
		});

	const issueToken = () =>
		run(async () => {
			const res = await mintBanAgentToken("fail2ban", "365d");
			setAgentToken(res.token);
			await queryClient.invalidateQueries({ queryKey: ["ban-agent-tokens"] });
		});

	const revokeToken = (id: number) =>
		run(async () => {
			await revokeBanAgentToken(id);
			setSaved(true);
			await queryClient.invalidateQueries({ queryKey: ["ban-agent-tokens"] });
		});

	return (
		<div className="card mt-4">
			<div className="card-status-top bg-orange" />
			<div className="card-header d-flex align-items-center gap-2">
				<h2 className="mt-1 mb-0 me-auto">
					<T id="bans" />
				</h2>
				<Button size="sm" variant="ghost" disabled={busy} onClick={issueToken}>
					<T id="bans.agent-token" />
				</Button>
				<Button size="sm" disabled={busy} onClick={() => setForm(emptyBanForm())}>
					<T id="bans.add" />
				</Button>
			</div>
			<div className="card-body">
				<Alert variant="danger" show={!!error} onClose={() => setError(null)} dismissible>
					<pre className="mb-0" style={{ whiteSpace: "pre-wrap" }}>
						{error}
					</pre>
				</Alert>
				<Alert variant="success" show={saved} onClose={() => setSaved(false)} dismissible>
					<T id="bans.saved" />
				</Alert>
				<Alert variant="info" show={!!agentToken} onClose={() => setAgentToken(null)} dismissible>
					<div className="small fw-semibold mb-1">
						<T id="bans.agent-token" />
					</div>
					<code style={{ wordBreak: "break-all" }}>{agentToken}</code>
				</Alert>

				{bans.isLoading ? (
					<Loading noLogo />
				) : bans.data?.length ? (
					<div className="table-responsive">
						<table className="table table-sm table-vcenter">
							<thead>
								<tr>
									<th>
										<T id="bans.ip" />
									</th>
									<th>
										<T id="block-rules.action" />
									</th>
									<th>
										<T id="bans.expires" />
									</th>
									<th>
										<T id="bans.source" />
									</th>
									<th>
										<T id="bans.reason" />
									</th>
									<th>
										<T id="block-rules.hits" />
									</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{bans.data.map((ban) => (
									<tr key={ban.id}>
										<td>
											<code>{ban.ip}</code>
										</td>
										<td>{ban.action}</td>
										<td>{ban.expiresOn}</td>
										<td>
											<code>{ban.source}</code>
										</td>
										<td>{ban.reason || "-"}</td>
										<td>
											<span>{ban.hitCount ?? 0}</span>
											{ban.lastHitOn ? <div className="text-secondary small">{ban.lastHitOn}</div> : null}
										</td>
										<td className="text-end text-nowrap">
											<Button
												size="sm"
												variant="ghost"
												actionType="danger"
												disabled={busy}
												onClick={() => unban(ban.id)}
											>
												<T id="bans.unban" />
											</Button>
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				) : (
					<p className="text-secondary mb-0">
						<T id="bans.empty" />
					</p>
				)}

				{form && (
					<div className="border-top pt-3 mt-3">
						<div className="row g-2 mb-2">
							<div className="col-md-4">
								<label className="form-label" htmlFor="ban-ip">
									<T id="bans.ip" />
								</label>
								<input
									id="ban-ip"
									className="form-control font-monospace"
									placeholder="203.0.113.10"
									value={form.ip}
									onChange={(e) => setForm({ ...form, ip: e.target.value })}
								/>
							</div>
							<div className="col-md-4">
								<label className="form-label" htmlFor="ban-action">
									<T id="block-rules.action" />
								</label>
								<select
									id="ban-action"
									className="form-select"
									value={form.action}
									onChange={(e) => setForm({ ...form, action: Number(e.target.value) as BlockRuleAction })}
								>
									<option value={403}>403</option>
									<option value={404}>404</option>
									<option value={444}>444</option>
								</select>
							</div>
							<div className="col-md-4">
								<label className="form-label" htmlFor="ban-ttl">
									<T id="bans.ttl" />
								</label>
								<input
									id="ban-ttl"
									type="number"
									min={1}
									max={31536000}
									className="form-control"
									value={form.ttlSeconds}
									onChange={(e) => setForm({ ...form, ttlSeconds: Number(e.target.value) || 1 })}
								/>
							</div>
						</div>
						<div className="mb-3">
							<label className="form-label" htmlFor="ban-reason">
								<T id="bans.reason" />
							</label>
							<input
								id="ban-reason"
								className="form-control"
								value={form.reason}
								onChange={(e) => setForm({ ...form, reason: e.target.value })}
							/>
						</div>
						<div className="d-flex gap-2">
							<Button
								actionType="primary"
								isLoading={busy}
								disabled={busy || !form.ip.trim() || form.ttlSeconds < 1}
								onClick={save}
							>
								<T id="save" />
							</Button>
							<Button disabled={busy} onClick={() => setForm(null)}>
								<T id="cancel" />
							</Button>
						</div>
					</div>
				)}

				{agentTokens.data && agentTokens.data.length > 0 && (
					<div className="border-top pt-3 mt-3">
						<h3 className="h5 mb-2">
							<T id="bans.agent-tokens" />
						</h3>
						<div className="table-responsive">
							<table className="table table-sm table-vcenter mb-0">
								<thead>
									<tr>
										<th>
											<T id="bans.source" />
										</th>
										<th>
											<T id="bans.expires" />
										</th>
										<th />
									</tr>
								</thead>
								<tbody>
									{agentTokens.data.map((tok) => (
										<tr key={tok.id}>
											<td>
												<code>{tok.label}</code>
												<span className="text-secondary small ms-2">
													#{tok.id} ({tok.jti.slice(0, 8)})
												</span>
											</td>
											<td>{tok.expiresOn}</td>
											<td className="text-end text-nowrap">
												{tok.isRevoked ? (
													<span className="badge bg-secondary-lt">
														<T id="bans.revoked" />
													</span>
												) : (
													<Button
														size="sm"
														variant="ghost"
														actionType="danger"
														disabled={busy}
														onClick={() => revokeToken(tok.id)}
													>
														<T id="bans.revoke-token" />
													</Button>
												)}
											</td>
										</tr>
									))}
								</tbody>
							</table>
						</div>
					</div>
				)}
			</div>
		</div>
	);
}
