import { useQuery } from "@tanstack/react-query";
import * as api from "src/api/backend/base";

export type BlockRuleType = "ip" | "ua" | "uri" | "uri_referer";
export type BlockRuleAction = 403 | 404 | 444;

export interface BlockRule {
	id: number;
	createdOn: string;
	modifiedOn: string;
	ownerUserId: number;
	type: BlockRuleType;
	pattern: string;
	refererPattern: string;
	action: BlockRuleAction;
	enabled: boolean;
	note: string;
	approvedBy: string;
	source: string;
	hitCount: number;
	lastHitOn: string | null;
}

export interface BlockRulePayload {
	type: BlockRuleType;
	pattern: string;
	refererPattern?: string;
	action: BlockRuleAction;
	enabled: boolean;
	note?: string;
	approvedBy?: string;
}

export const useBlockRules = () =>
	useQuery<BlockRule[], Error>({
		queryKey: ["block-rules"],
		queryFn: () => api.get({ url: "/nginx/block-rules" }),
	});

export const createBlockRule = async (data: BlockRulePayload): Promise<BlockRule> =>
	await api.post({ url: "/nginx/block-rules", data });

export const updateBlockRule = async (id: number, data: Partial<BlockRulePayload>): Promise<BlockRule> =>
	await api.put({ url: `/nginx/block-rules/${id}`, data });

export const toggleBlockRule = async (id: number, enabled: boolean): Promise<boolean> =>
	await api.post({ url: `/nginx/block-rules/${id}/${enabled ? "enable" : "disable"}` });

export const deleteBlockRule = async (id: number): Promise<boolean> =>
	await api.del({ url: `/nginx/block-rules/${id}` });

export interface IpBan {
	id: number;
	createdOn: string;
	modifiedOn: string;
	expiresOn: string;
	ip: string;
	action: BlockRuleAction;
	reason: string;
	source: string;
	hitCount: number;
	lastHitOn: string | null;
}

export interface IpBanPayload {
	ip: string;
	action: BlockRuleAction;
	ttlSeconds: number;
	reason?: string;
}

export interface AgentTokenResponse {
	id: number;
	jti: string;
	token: string;
	expires: string;
	scope: string;
	label: string;
}

export interface BanAgentTokenRecord {
	id: number;
	createdOn: string;
	modifiedOn: string;
	expiresOn: string;
	isRevoked: boolean;
	jti: string;
	label: string;
	createdBy: number;
}

export const useIpBans = () =>
	useQuery<IpBan[], Error>({
		queryKey: ["ip-bans"],
		queryFn: () => api.get({ url: "/nginx/bans" }),
	});

export const useBanAgentTokens = () =>
	useQuery<BanAgentTokenRecord[], Error>({
		queryKey: ["ban-agent-tokens"],
		queryFn: () => api.get({ url: "/nginx/bans/agent-tokens" }),
	});

export const createIpBan = async (data: IpBanPayload): Promise<IpBan> =>
	await api.post({ url: "/nginx/bans", data });

export const revokeIpBan = async (id: number): Promise<boolean> =>
	await api.del({ url: `/nginx/bans/${id}` });

export const mintBanAgentToken = async (label = "ban-agent", expiry = "365d"): Promise<AgentTokenResponse> =>
	await api.post({ url: "/nginx/bans/agent-token", data: { label, expiry } });

export const revokeBanAgentToken = async (id: number): Promise<boolean> =>
	await api.del({ url: `/nginx/bans/agent-tokens/${id}` });
