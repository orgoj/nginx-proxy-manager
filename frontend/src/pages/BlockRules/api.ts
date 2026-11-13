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
