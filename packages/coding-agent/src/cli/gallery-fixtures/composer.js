import { renderComposerShapePreview } from "@rva/tui/overlays/composer-shape-preview";
import { getComposerShapeOptions } from "@rva/tui/overlays/composer-shape-registry";
import { StatusLineComponent } from "@rva/tui/status-line";
import { statusLineHost } from "../../modes/status-line-host";
import { createGallerySession } from "./preview-session";
/** Production composer registry in selector order. */
export function getComposerGalleryInventory() {
    return getComposerShapeOptions().map(option => option.value);
}
function renderComposer(shape, width) {
    const status = new StatusLineComponent(createGallerySession(), statusLineHost);
    status.updateSettings({
        preset: "custom",
        leftSegments: ["pi", "model", "mode"],
        rightSegments: ["session_name", "context_pct"],
        separator: "powerline-thin",
        sessionAccent: false,
        contextLine: "annotated",
    });
    status.setPlanModeStatus({ enabled: true, paused: false });
    try {
        return renderComposerShapePreview(shape, width, status);
    }
    finally {
        status.dispose();
    }
}
/** Every registered composer style, rendered through the production preview. */
export function getComposerGalleryEntries() {
    return getComposerShapeOptions().map(option => ({
        id: option.value,
        heading: `composer · ${option.value} — ${option.label}`,
        variants: [
            {
                label: "canonical preview",
                render: width => renderComposer(option.value, width),
            },
        ],
    }));
}
