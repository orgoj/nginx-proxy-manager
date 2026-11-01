import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import errs from "../lib/error.js";
import withNginxLock from "../lib/nginx-lock.js";
import { nginx as logger } from "../logger.js";
import internalNginx from "./nginx.js";

// Admin editor for the plain config files NPM already loads:
// - nginx: /data/nginx/custom/*.conf (fixed include points, plus own files
//   included from them); every change is checked with nginx -t and rolled back
//   on failure, then nginx reloads.
// - logrotate: /data/logrotate.d/*.conf, rotated by the logrotate s6 service;
//   checked with logrotate -d before it replaces the live file.
// The directory comes from this fixed table, never from the client; names are
// plain *.conf file names; symlinks are never followed.
const DIRS = {
	nginx: "/data/nginx/custom",
	logrotate: "/data/logrotate.d",
};
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,94}\.conf$/;
const MAX_BYTES = 64 * 1024;
const LOGROTATE_DEBUG_NOTICE = "logrotate in debug mode does nothing";

const resolveTarget = (dir, name) => {
	if (!Object.hasOwn(DIRS, dir)) {
		throw new errs.ItemNotFoundError(dir);
	}
	if (typeof name !== "string" || !NAME_RE.test(name)) {
		throw new errs.ValidationError("File name must look like name.conf (letters, digits, . _ -)");
	}
	return { dirPath: DIRS[dir], path: `${DIRS[dir]}/${name}` };
};

const ensureDir = async (dirPath) => {
	await fs.promises.mkdir(dirPath, { recursive: true, mode: 0o755 });
	const st = await fs.promises.lstat(dirPath);
	if (!st.isDirectory()) {
		throw new errs.ValidationError(`${dirPath} is not a directory`);
	}
};

// Returns the file content, or null when the file does not exist.
const readFile = async (path) => {
	let handle;
	try {
		handle = await fs.promises.open(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
		const st = await handle.stat();
		if (!st.isFile()) {
			throw new errs.ValidationError(`${path} is not a regular file`);
		}
		if (st.size > MAX_BYTES) {
			throw new errs.ValidationError(`${path} is larger than ${MAX_BYTES} bytes, edit it on disk`);
		}
		return await handle.readFile({ encoding: "utf8" });
	} catch (err) {
		if (err.code === "ENOENT") {
			return null;
		}
		if (err.code === "ELOOP") {
			throw new errs.ValidationError(`${path} is a symlink`);
		}
		throw err;
	} finally {
		await handle?.close();
	}
};

// Writes a new, exclusively created temp file next to the target (never
// matching *.conf) and returns its path. O_EXCL refuses an existing symlink.
const writeTemp = async (dirPath, name, content) => {
	const tmp = `${dirPath}/.${name}.${randomBytes(6).toString("hex")}.tmp`;
	const handle = await fs.promises.open(tmp, "wx", 0o644);
	try {
		await handle.writeFile(content, { encoding: "utf8" });
		await handle.chmod(0o644);
		await handle.sync();
	} finally {
		await handle.close();
	}
	return tmp;
};

const removeQuietly = async (path) => {
	await fs.promises.unlink(path).catch((err) => {
		if (err.code !== "ENOENT") throw err;
	});
};

// Atomically puts content at path (rename replaces a symlink, never follows
// it), or removes path when content is null.
const putFile = async (dirPath, name, path, content) => {
	if (content === null) {
		await removeQuietly(path);
		return;
	}
	const tmp = await writeTemp(dirPath, name, content);
	try {
		await fs.promises.rename(tmp, path);
	} catch (err) {
		await removeQuietly(tmp);
		throw err;
	}
};

const nginxError = (err) => {
	// Same docker-ism false positive that internalNginx.configure drops.
	const lines = String(err?.message || err)
		.split("\n")
		.filter((line) => line.indexOf("/var/log/nginx/error.log") === -1);
	return new errs.ValidationError(lines.join("\n").trim() || "nginx configuration test failed");
};

// Applies the change, then nginx -t + reload; on any failure restores the
// previous file state and reloads that.
const nginxTransaction = (dirPath, name, path, content) =>
	withNginxLock(async () => {
		await ensureDir(dirPath);
		const previous = await readFile(path);
		if (content === null && previous === null) {
			throw new errs.ItemNotFoundError(name);
		}
		await putFile(dirPath, name, path, content);
		try {
			await internalNginx.reload();
		} catch (err) {
			await putFile(dirPath, name, path, previous);
			await internalNginx.reload().catch((reloadErr) => {
				logger.error(`Reload after restoring ${path} failed: ${reloadErr.message}`);
			});
			throw nginxError(err);
		}
		logger.info(`Custom nginx file ${content === null ? "deleted" : "saved"}: ${path}`);
	});

const logrotateCheck = (file) =>
	new Promise((resolve) => {
		execFile(
			"/usr/sbin/logrotate",
			["-d", "-s", "/dev/null", file],
			{ timeout: 30000 },
			(err, stdout, stderr) => {
				const problems = `${stdout}\n${stderr}`
					.split("\n")
					.filter((line) => /^(error|warning):/.test(line) && line.indexOf(LOGROTATE_DEBUG_NOTICE) === -1)
					.map((line) => line.split(file).join("<file>"));
				if (err && !problems.length) {
					problems.push(`logrotate -d failed: ${err.message}`);
				}
				resolve(problems);
			},
		);
	});

const logrotateSave = async (dirPath, name, path, content) => {
	await ensureDir(dirPath);
	await readFile(path); // refuses a symlink or non-regular target
	const tmp = await writeTemp(dirPath, name, content);
	try {
		const problems = await logrotateCheck(tmp);
		if (problems.length) {
			throw new errs.ValidationError(problems.join("\n"));
		}
		await fs.promises.rename(tmp, path);
	} catch (err) {
		await removeQuietly(tmp);
		throw err;
	}
	logger.info(`Custom logrotate file saved: ${path}`);
};

const listDir = async (dirPath) => {
	let entries;
	try {
		entries = await fs.promises.readdir(dirPath, { withFileTypes: true });
	} catch (err) {
		if (err.code === "ENOENT") return [];
		throw err;
	}
	const files = [];
	for (const entry of entries) {
		if (entry.isFile() && NAME_RE.test(entry.name)) {
			const st = await fs.promises.lstat(`${dirPath}/${entry.name}`);
			files.push({ name: entry.name, size: st.size, modified: st.mtime.toISOString() });
		}
	}
	return files.sort((a, b) => a.name.localeCompare(b.name));
};

const internalCustomFile = {
	getAll: async (access) => {
		await access.can("custom_files:manage");
		const result = {};
		for (const dir of Object.keys(DIRS)) {
			result[dir] = await listDir(DIRS[dir]);
		}
		return result;
	},

	get: async (access, { dir, name }) => {
		await access.can("custom_files:manage");
		const { path } = resolveTarget(dir, name);
		const content = await readFile(path);
		if (content === null) {
			throw new errs.ItemNotFoundError(name);
		}
		return { dir, name, content };
	},

	save: async (access, { dir, name, content }) => {
		await access.can("custom_files:manage");
		const { dirPath, path } = resolveTarget(dir, name);
		if (typeof content !== "string" || Buffer.byteLength(content) > MAX_BYTES || content.includes("\0")) {
			throw new errs.ValidationError(`Content must be text up to ${MAX_BYTES} bytes`);
		}
		if (dir === "nginx") {
			await nginxTransaction(dirPath, name, path, content);
		} else {
			await logrotateSave(dirPath, name, path, content);
		}
		return { dir, name, content };
	},

	delete: async (access, { dir, name }) => {
		await access.can("custom_files:manage");
		const { dirPath, path } = resolveTarget(dir, name);
		if (dir === "nginx") {
			await nginxTransaction(dirPath, name, path, null);
		} else {
			if ((await readFile(path)) === null) {
				throw new errs.ItemNotFoundError(name);
			}
			await fs.promises.unlink(path);
			logger.info(`Custom logrotate file deleted: ${path}`);
		}
		return true;
	},
};

export default internalCustomFile;
