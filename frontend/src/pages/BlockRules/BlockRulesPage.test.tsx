import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import BlockRulesPage from "./BlockRulesPage";

const { apiMock } = vi.hoisted(() => ({
	apiMock: {
		createBlockRule: vi.fn(),
		updateBlockRule: vi.fn(),
		toggleBlockRule: vi.fn(),
		deleteBlockRule: vi.fn(),
		createIpBan: vi.fn(),
		revokeIpBan: vi.fn(),
		mintBanAgentToken: vi.fn(),
		revokeBanAgentToken: vi.fn(),
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
	useIpBans: () => ({
		isLoading: false,
		data: [
			{
				id: 9,
				createdOn: "2026-11-13T11:00:00.000Z",
				modifiedOn: "2026-11-13T11:00:00.000Z",
				expiresOn: "2026-11-13T12:00:00.000Z",
				ip: "198.51.100.77",
				action: 403,
				reason: "ssh brute",
				source: "agent:3:fail2ban",
			},
		],
	}),
	useBanAgentTokens: () => ({
		isLoading: false,
		data: [
			{
				id: 3,
				createdOn: "2026-11-13T11:00:00.000Z",
				modifiedOn: "2026-11-13T11:00:00.000Z",
				expiresOn: "2027-11-13T00:00:00.000Z",
				isRevoked: false,
				jti: "abcdef1234567890",
				label: "fail2ban",
				createdBy: 1,
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

	it("renders active temporary bans and supports banning, unbanning, minting, and revoking agent token", async () => {
		apiMock.createIpBan.mockResolvedValueOnce({ id: 10 });
		apiMock.revokeIpBan.mockResolvedValueOnce(true);
		apiMock.mintBanAgentToken.mockResolvedValueOnce({
			id: 4,
			jti: "deadbeef1234",
			token: "ban-agent-jwt-sample",
			expires: "2027-11-13T00:00:00.000Z",
			scope: "ban-agent",
			label: "fail2ban",
		});
		apiMock.revokeBanAgentToken.mockResolvedValueOnce(true);

		renderPage();
		expect(screen.getByText("198.51.100.77")).toBeVisible();
		expect(screen.getByText("ssh brute")).toBeVisible();

		fireEvent.click(screen.getByRole("button", { name: "Ban IP" }));
		fireEvent.change(screen.getByLabelText("IP Address"), { target: { value: "203.0.113.55" } });
		fireEvent.click(screen.getAllByRole("button", { name: "Save" })[0]);
		expect(apiMock.createIpBan).toHaveBeenCalledWith({
			ip: "203.0.113.55",
			action: 403,
			ttlSeconds: 3600,
			reason: "",
		});
		await waitFor(() => expect(screen.getByRole("button", { name: "Unban" })).toBeEnabled());

		fireEvent.click(screen.getByRole("button", { name: "Unban" }));
		await waitFor(() => expect(apiMock.revokeIpBan).toHaveBeenCalledWith(9));
		await waitFor(() => expect(screen.getByRole("button", { name: "Ban Agent Token" })).toBeEnabled());

		fireEvent.click(screen.getByRole("button", { name: "Ban Agent Token" }));
		expect(await screen.findByText("ban-agent-jwt-sample")).toBeVisible();

		await waitFor(() => expect(screen.getByRole("button", { name: "Revoke" })).toBeEnabled());
		fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
		await waitFor(() => expect(apiMock.revokeBanAgentToken).toHaveBeenCalledWith(3));
	});
});
