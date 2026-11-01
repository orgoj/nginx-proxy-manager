import { HasPermission } from "src/components";
import { ADMIN, VIEW } from "src/modules/Permissions";
import CustomFilesEditor from "./CustomFilesEditor";

const CustomFiles = () => {
	return (
		<HasPermission section={ADMIN} permission={VIEW} pageLoading loadingNoLogo>
			<CustomFilesEditor />
		</HasPermission>
	);
};

export default CustomFiles;
