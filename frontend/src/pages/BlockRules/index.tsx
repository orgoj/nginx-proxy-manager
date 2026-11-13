import { HasPermission } from "src/components";
import { ADMIN, VIEW } from "src/modules/Permissions";
import BlockRulesPage from "./BlockRulesPage";

const BlockRules = () => {
	return (
		<HasPermission section={ADMIN} permission={VIEW} pageLoading loadingNoLogo>
			<BlockRulesPage />
		</HasPermission>
	);
};

export default BlockRules;
