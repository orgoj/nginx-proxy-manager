import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import { Button, Loading } from "src/components";
import { formatDateTime, getLocale, T } from "src/locale";
import { showDeleteConfirmModal } from "src/modals";
import {
	type CustomFileDir,
	deleteCustomFile,
	getCustomFile,
	saveCustomFile,
	useCustomFiles,
} from "./api";

const DIRS: { dir: CustomFileDir; path: string }[] = [
	{ dir: "nginx", path: "/data/nginx/custom" },
	{ dir: "logrotate", path: "/data/logrotate.d" },
];
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,94}\.conf$/;

interface Editing {
	dir: CustomFileDir;
	name: string;
	isNew: boolean;
	content: string;
}

export default function CustomFilesEditor() {
	const queryClient = useQueryClient();
	const files = useCustomFiles();
	const [editing, setEditing] = useState<Editing | null>(null);
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

	const openFile = (dir: CustomFileDir, name: string) =>
		run(async () => {
			const file = await getCustomFile(dir, name);
			setEditing({ dir, name, isNew: false, content: file.content });
		});

	const save = () =>
		run(async () => {
			if (!editing) return;
			await saveCustomFile(editing.dir, editing.name, editing.content);
			setEditing({ ...editing, isNew: false });
			setSaved(true);
			await queryClient.invalidateQueries({ queryKey: ["custom-files"] });
		});

	const confirmDelete = (dir: CustomFileDir, name: string) =>
		showDeleteConfirmModal({
			title: <T id="action.delete" />,
			children: <T id="custom-files.delete-confirm" data={{ name: `${dir}/${name}` }} />,
			invalidations: [["custom-files"]],
			onConfirm: async () => {
				await deleteCustomFile(dir, name);
				if (editing?.dir === dir && editing.name === name) {
					setEditing(null);
				}
			},
		});

	return (
		<div className="card mt-4">
			<div className="card-status-top bg-purple" />
			<div className="card-header">
				<h2 className="mt-1 mb-0">
					<T id="custom-files" />
				</h2>
			</div>
			<div className="card-body">
				<Alert variant="danger" show={!!error} onClose={() => setError(null)} dismissible>
					<pre className="mb-0" style={{ whiteSpace: "pre-wrap" }}>
						{error}
					</pre>
				</Alert>
				<Alert variant="success" show={saved} onClose={() => setSaved(false)} dismissible>
					<T id="custom-files.saved" />
				</Alert>
				{files.isLoading ? (
					<Loading noLogo />
				) : (
					DIRS.map(({ dir, path }) => (
						<div key={dir} className="mb-4">
							<div className="d-flex align-items-center mb-2">
								<h3 className="mb-0 me-auto">
									<code>{path}</code>
								</h3>
								<Button
									size="sm"
									disabled={busy}
									onClick={() => setEditing({ dir, name: "", isNew: true, content: "" })}
								>
									<T id="action.add" />
								</Button>
							</div>
							{files.data?.[dir]?.length ? (
								<table className="table table-sm table-vcenter">
									<thead>
										<tr>
											<th>
												<T id="column.name" />
											</th>
											<th>
												<T id="custom-files.size" />
											</th>
											<th>
												<T id="custom-files.modified" />
											</th>
											<th />
										</tr>
									</thead>
									<tbody>
										{files.data[dir].map((file) => (
											<tr key={file.name}>
												<td>
													<code>{file.name}</code>
												</td>
												<td>{file.size} B</td>
												<td>{formatDateTime(file.modified, getLocale())}</td>
												<td className="text-end">
													<Button
														size="sm"
														variant="ghost"
														disabled={busy}
														onClick={() => openFile(dir, file.name)}
													>
														<T id="action.edit" />
													</Button>
													<Button
														size="sm"
														variant="ghost"
														actionType="danger"
														disabled={busy}
														onClick={() => confirmDelete(dir, file.name)}
													>
														<T id="action.delete" />
													</Button>
												</td>
											</tr>
										))}
									</tbody>
								</table>
							) : (
								<p className="text-secondary">
									<T id="custom-files.empty" />
								</p>
							)}
						</div>
					))
				)}
				{editing && (
					<div className="border-top pt-3">
						{editing.isNew ? (
							<input
								className="form-control mb-2"
								aria-label="file name"
								placeholder="name.conf"
								value={editing.name}
								onChange={(e) => setEditing({ ...editing, name: e.target.value })}
							/>
						) : (
							<h3>
								<code>
									{editing.dir}/{editing.name}
								</code>
							</h3>
						)}
						<textarea
							className="form-control font-monospace mb-2"
							aria-label="file content"
							rows={20}
							spellCheck={false}
							value={editing.content}
							onChange={(e) => setEditing({ ...editing, content: e.target.value })}
						/>
						<div className="d-flex gap-2">
							<Button
								actionType="primary"
								isLoading={busy}
								disabled={busy || !NAME_RE.test(editing.name)}
								onClick={save}
							>
								<T id="save" />
							</Button>
							<Button disabled={busy} onClick={() => setEditing(null)}>
								<T id="cancel" />
							</Button>
						</div>
					</div>
				)}
			</div>
		</div>
	);
}
