import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import BlockRulesPage from "./BlockRulesPage";

const { apiMock } = vi.hoisted(() => ({
	apiMock: {
		createBlockRule: vi.fn(),
		updateBlockRule: vi.fn(),
		toggleBlockRule: vi.fn(),
		deleteBlockRule: vi.fn(),
	},
}));

vi.mock("./api", () => ({
	...apiMock,
	useBlockRules: () => ({
		isLoading: false,
		data: [
			{
				id: 1,
				createdOn: "2026-11-13T10:00:00.000Z",
				modifiedOn: "2026-11-13T10:00:00.000Z",
				ownerUserId: 1,
				type: "ua",
				pattern: "(semrush|mj12bot)",
				refererPattern: "",
				action: 403,
				enabled: true,
				note: "crawlers",
				approvedBy: "michael",
				source: "ui",
			},
		],
	}),
}));
vi.mock("src/modals", () => ({ showDeleteConfirmModal: vi.fn() }));

const renderPage = () =>
	render(
		<QueryClientProvider client={new QueryClient()}>
			<BlockRulesPage />
		</QueryClientProvider>,
	);

describe("BlockRulesPage", () => {
	afterEach(() => {
		cleanup();
		vi.clearAllMocks();
	});

	it("renders configured global block rules", () => {
		renderPage();
		expect(screen.getByText("(semrush|mj12bot)")).toBeVisible();
		expect(screen.getByText("crawlers")).toBeVisible();
		expect(screen.getByText("michael")).toBeVisible();
	});

	it("creates a new rule and shows validation errors from the API", async () => {
		apiMock.createBlockRule.mockRejectedValueOnce(new Error("Invalid IP address: bogus"));
		renderPage();

		fireEvent.click(screen.getByRole("button", { name: "Add" }));
		fireEvent.change(screen.getByLabelText("Type"), { target: { value: "ip" } });
		fireEvent.change(screen.getByLabelText("Pattern"), { target: { value: "bogus" } });
		fireEvent.click(screen.getByRole("button", { name: "Save" }));

		expect(await screen.findByText("Invalid IP address: bogus")).toBeVisible();
		expect(apiMock.createBlockRule).toHaveBeenCalledWith({
			type: "ip",
			pattern: "bogus",
			refererPattern: "",
			action: 403,
			enabled: true,
			note: "",
			approvedBy: "",
		});
	});

	it("requires referer pattern for uri_referer rules", () => {
		renderPage();
		fireEvent.click(screen.getByRole("button", { name: "Add" }));
		fireEvent.change(screen.getByLabelText("Type"), { target: { value: "uri_referer" } });
		fireEvent.change(screen.getByLabelText("Pattern"), { target: { value: "^/shop" } });

		const save = screen.getByRole("button", { name: "Save" });
		expect(save).toBeDisabled();

		fireEvent.change(screen.getByLabelText("Referer Pattern"), { target: { value: "spam\\.test" } });
		expect(save).toBeEnabled();
	});
});
