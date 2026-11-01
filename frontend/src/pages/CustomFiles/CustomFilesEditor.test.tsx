import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import CustomFilesEditor from "./CustomFilesEditor";

const { apiMock } = vi.hoisted(() => ({
	apiMock: {
		getCustomFile: vi.fn(),
		saveCustomFile: vi.fn(),
		deleteCustomFile: vi.fn(),
	},
}));

vi.mock("./api", () => ({
	...apiMock,
	useCustomFiles: () => ({
		isLoading: false,
		data: {
			nginx: [{ name: "http.conf", size: 12, modified: "2026-11-01T10:00:00.000Z" }],
			logrotate: [],
		},
	}),
}));
vi.mock("src/modals", () => ({ showDeleteConfirmModal: vi.fn() }));

const renderEditor = () =>
	render(
		<QueryClientProvider client={new QueryClient()}>
			<CustomFilesEditor />
		</QueryClientProvider>,
	);

describe("CustomFilesEditor", () => {
	afterEach(() => {
		cleanup();
		vi.clearAllMocks();
	});

	it("lists the files of both directories", () => {
		renderEditor();
		expect(screen.getByText("/data/nginx/custom")).toBeVisible();
		expect(screen.getByText("/data/logrotate.d")).toBeVisible();
		expect(screen.getByText("http.conf")).toBeVisible();
		expect(screen.getByText("No files")).toBeVisible();
	});

	it("shows the nginx -t error when a save is refused", async () => {
		apiMock.getCustomFile.mockResolvedValue({ content: "map $a $b {}" });
		apiMock.saveCustomFile.mockRejectedValue(new Error('nginx: [emerg] unknown directive "bogus"'));
		renderEditor();

		fireEvent.click(screen.getByRole("button", { name: "Edit" }));
		const content = await screen.findByLabelText("file content");
		expect(content).toHaveValue("map $a $b {}");
		fireEvent.change(content, { target: { value: "bogus;" } });
		fireEvent.click(screen.getByRole("button", { name: "Save" }));

		expect(await screen.findByText('nginx: [emerg] unknown directive "bogus"')).toBeVisible();
		expect(apiMock.saveCustomFile).toHaveBeenCalledWith("nginx", "http.conf", "bogus;");
	});

	it("allows saving a new file only with a valid *.conf name", () => {
		renderEditor();
		fireEvent.click(screen.getAllByRole("button", { name: "Add" })[1]);
		const name = screen.getByLabelText("file name");
		const save = screen.getByRole("button", { name: "Save" });

		for (const bad of ["../x.conf", ".hidden.conf", "x.txt", "a/b.conf"]) {
			fireEvent.change(name, { target: { value: bad } });
			expect(save).toBeDisabled();
		}
		fireEvent.change(name, { target: { value: "weblog.conf" } });
		expect(save).toBeEnabled();
	});
});
