import { appearanceSettingsZhCN } from "./appearance";
import { modelSettingsZhCN } from "./model";
import { interactionSettingsZhCN } from "./interaction";
import { contextSettingsZhCN } from "./context";
import { memorySettingsZhCN } from "./memory";
import { filesSettingsZhCN } from "./files";
import { shellSettingsZhCN } from "./shell";
import { toolsSettingsZhCN } from "./tools";
import { tasksSettingsZhCN } from "./tasks";
import { providersSettingsZhCN } from "./providers";
/** Every user-visible setting, keyed by its canonical setting id. */
export const SETTING_TRANSLATIONS_ZH_CN = {
    ...appearanceSettingsZhCN,
    ...modelSettingsZhCN,
    ...interactionSettingsZhCN,
    ...contextSettingsZhCN,
    ...memorySettingsZhCN,
    ...filesSettingsZhCN,
    ...shellSettingsZhCN,
    ...toolsSettingsZhCN,
    ...tasksSettingsZhCN,
    ...providersSettingsZhCN,
};
