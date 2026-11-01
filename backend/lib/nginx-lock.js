// Serialises nginx config transactions (write, nginx -t, rollback, reload), so
// a custom file under test never overlaps with a host config being generated.
let tail = Promise.resolve();

const withNginxLock = (fn) => {
	const run = tail.then(fn, fn);
	tail = run.catch(() => {});
	return run;
};

export default withNginxLock;
