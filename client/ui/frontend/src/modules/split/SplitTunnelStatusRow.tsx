import { useTranslation } from "react-i18next";
import { AppWindowIcon } from "lucide-react";
import { Badge } from "@/components/Badge";
import { useSplitTunnel } from "@/contexts/SplitTunnelContext";
import { useFocusVisible } from "@/hooks/useFocusVisible";
import { cn } from "@/lib/cn";

// Entry row in the simple (default) view: opens the App split tunneling
// section of the advanced view, badge mirrors the current on/off state.
export const SplitTunnelStatusRow = ({ onClick }: { onClick: () => void }) => {
    const { t } = useTranslation();
    const { settings } = useSplitTunnel();
    const isFocusVisible = useFocusVisible();

    const enabled = !!settings && settings.mode !== "off";
    const count = settings?.apps.length ?? 0;

    return (
        <button
            type={"button"}
            tabIndex={0}
            onClick={onClick}
            aria-label={t("apps.split.entry.title")}
            className={cn(
                "flex w-full items-center gap-3 rounded-xl p-2.5 pe-4 text-start outline-hidden",
                "border border-nb-gray-800 bg-nb-gray-940 dark:border-nb-gray-920",
                "transition-colors duration-150",
                "wails-no-draggable",
                isFocusVisible &&
                    "focus-visible:ring-2 focus-visible:ring-nb-gray-50/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                "cursor-default hover:border-nb-gray-700 hover:bg-nb-gray-935 dark:hover:border-nb-gray-900",
            )}
        >
            <div
                aria-hidden={"true"}
                className={cn(
                    "flex h-9 w-9 shrink-0 items-center justify-center rounded-md",
                    enabled ? "bg-netbird/15 text-netbird" : "bg-nb-gray-900 text-nb-gray-300",
                )}
            >
                <AppWindowIcon size={14} />
            </div>
            <span className={"min-w-0 flex-1 truncate text-sm font-medium text-nb-gray-100"}>
                {t("apps.split.entry.title")}
            </span>
            {enabled ? (
                <Badge variant={"brand"}>{t("apps.split.status.on", { count })}</Badge>
            ) : (
                <Badge variant={"neutral"}>{t("apps.split.status.off")}</Badge>
            )}
        </button>
    );
};
