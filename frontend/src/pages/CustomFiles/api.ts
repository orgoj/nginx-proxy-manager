import { useQuery } from "@tanstack/react-query";
import * as api from "src/api/backend/base";

export type CustomFileDir = "nginx" | "logrotate";

export interface CustomFileInfo {
	name: string;
	size: number;
	modified: string;
}

export type CustomFileList = Record<CustomFileDir, CustomFileInfo[]>;

const fileUrl = (dir: CustomFileDir, name: string) => `/custom-files/${dir}/${encodeURIComponent(name)}`;

export const getCustomFile = async (dir: CustomFileDir, name: string): Promise<{ content: string }> =>
	await api.get({ url: fileUrl(dir, name) });

export const saveCustomFile = async (dir: CustomFileDir, name: string, content: string) =>
	await api.put({ url: fileUrl(dir, name), data: { content } });

export const deleteCustomFile = async (dir: CustomFileDir, name: string) => await api.del({ url: fileUrl(dir, name) });

export const useCustomFiles = () =>
	useQuery<CustomFileList, Error>({
		queryKey: ["custom-files"],
		queryFn: () => api.get({ url: "/custom-files" }),
	});
