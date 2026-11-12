import { type KeyboardEvent, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { AppWindowIcon, PlusIcon, XIcon } from "lucide-react";
import { Button } from "@/components/buttons/Button";
import { IconButton } from "@/components/buttons/IconButton";
import { EmptyState } from "@/components/empty-state/EmptyState";
import { SearchInput } from "@/components/inputs/SearchInput";
import { Select, type SelectOption } from "@/components/inputs/Select";
import { TruncatedText } from "@/components/TruncatedText";
import { HelpText } from "@/components/typography/HelpText";
import { Label } from "@/components/typography/Label";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { SettingsSkeleton } from "@/modules/settings/SettingsSkeleton.tsx";
import { useSplitTunnel, type SplitTunnelMode } from "@/contexts/SplitTunnelContext";
import { SplitTunnel as SplitTunnelSvc } from "@bindings/services";

const MAX_MATCHES = 10;
const DUPLICATE_WARNING_MS = 2000;

// basename of a native path, tolerating both separators (the dialog returns
// platform paths; the web view may run on another OS).
const basename = (path: string): string => path.split(/[\\/]+/).pop() ?? path;

export function SettingsApps() {
    const { t } = useTranslation();
    const {
        loading,
        applying,
        settings,
        runningApps,
        error,
        addApp,
        removeApp,
        setMode,
        hasChanges,
        save,
    } = useSplitTunnel();

    const [query, setQuery] = useState("");
    const [duplicate, setDuplicate] = useState(false);
    const inputRef = useRef<HTMLInputElement>(null);
    const duplicateTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

    useEffect(
        () => () => {
            if (duplicateTimer.current) clearTimeout(duplicateTimer.current);
        },
        [],
    );

    const showDuplicate = () => {
        setDuplicate(true);
        if (duplicateTimer.current) clearTimeout(duplicateTimer.current);
        duplicateTimer.current = setTimeout(() => setDuplicate(false), DUPLICATE_WARNING_MS);
    };

    const modeOptions = useMemo<SelectOption<SplitTunnelMode>[]>(
        () => [
            { value: "off", label: t("apps.split.mode.off") },
            { value: "include", label: t("apps.split.mode.include") },
            { value: "exclude", label: t("apps.split.mode.exclude") },
        ],
        [t],
    );

    const nameByExe = useMemo(
        () => new Map(runningApps.map((app) => [app.exe, app.name])),
        [runningApps],
    );

    const added = useMemo(() => new Set(settings?.apps ?? []), [settings]);

    const normalizedQuery = useMemo(() => query.trim().toLowerCase(), [query]);

    // Live matches from the running apps, filtered by the typed text; apps
    // already in the list stay out of the dropdown.
    const matches = useMemo(() => {
        if (!normalizedQuery) return [];
        return runningApps
            .filter(
                (app) =>
                    !added.has(app.exe) &&
                    (app.name.toLowerCase().includes(normalizedQuery) ||
                        app.exe.toLowerCase().includes(normalizedQuery) ||
                        app.path.toLowerCase().includes(normalizedQuery)),
            )
            .slice(0, MAX_MATCHES);
    }, [normalizedQuery, runningApps, added]);

    // The query also filters the selected list.
    const visibleApps = useMemo(() => {
        const apps = settings?.apps ?? [];
        if (!normalizedQuery) return apps;
        return apps.filter((exe) => exe.includes(normalizedQuery));
    }, [settings, normalizedQuery]);

    // Returns false (and shows the inline warning) when the app is already
    // in the list; the typed text itself never becomes an app.
    const commit = (exe: string): boolean => {
        if (!addApp(exe)) {
            showDuplicate();
            return false;
        }
        setQuery("");
        inputRef.current?.focus();
        return true;
    };

    // Enter picks the first dropdown match; with nothing matching, Enter adds
    // nothing: an app enters the list only via the dropdown or the file dialog.
    const onSearchKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
        if (e.key !== "Enter") return;
        e.preventDefault();
        if (matches.length > 0) commit(matches[0].exe);
    };

    const onPickFile = async () => {
        try {
            const path = await SplitTunnelSvc.PickAppExe();
            // Empty path means the dialog was cancelled.
            if (path) commit(basename(path));
        } catch (e) {
            console.error("[SettingsApps] pick executable failed", e);
        }
    };

    return (
        <SectionGroup title={t("apps.split.title")}>
            <HelpText margin={false}>{t("apps.split.description")}</HelpText>
            {!settings ? (
                <SettingsSkeleton />
            ) : (
                <>
                    <div className={"flex items-center justify-between gap-6"}>
                        <div className={"max-w-md flex-1"}>
                            <Label as={"div"}>{t("apps.split.mode.label")}</Label>
                        </div>
                        <div className={"shrink-0"}>
                            <Select
                                value={settings.mode}
                                options={modeOptions}
                                onChange={setMode}
                                ariaLabel={t("apps.split.mode.label")}
                            />
                        </div>
                    </div>

                    <div className={"relative"}>
                        <Label as={"div"}>{t("apps.split.add.label")}</Label>
                        <div className={"flex items-center gap-2"}>
                            <div
                                className={
                                    "flex min-w-0 flex-1 items-center rounded-md border border-nb-gray-850 bg-nb-gray-920 focus-within:border-nb-gray-700"
                                }
                            >
                                <SearchInput
                                    ref={inputRef}
                                    placeholder={t("apps.split.add.placeholder")}
                                    value={query}
                                    onChange={(e) => setQuery(e.target.value)}
                                    onKeyDown={onSearchKeyDown}
                                />
                            </div>
                            <IconButton
                                icon={PlusIcon}
                                aria-label={t("apps.split.add.pickFile")}
                                title={t("apps.split.add.pickFile")}
                                onClick={() => onPickFile()}
                                className={"h-10 w-10 shrink-0"}
                            />
                        </div>
                        {duplicate && (
                            <p role={"status"} className={"mt-1 text-xs font-medium text-red-500"}>
                                {t("apps.split.add.duplicate")}
                            </p>
                        )}
                        {matches.length > 0 && (
                            <div
                                role={"listbox"}
                                aria-label={t("apps.split.add.label")}
                                className={
                                    "absolute inset-x-0 top-full z-10 mt-1 flex flex-col rounded-md border border-nb-gray-850 bg-nb-gray-920 py-1 shadow-lg"
                                }
                            >
                                {matches.map((app) => (
                                    <button
                                        key={app.exe}
                                        type={"button"}
                                        role={"option"}
                                        aria-selected={"false"}
                                        onMouseDown={(e) => e.preventDefault()}
                                        onClick={() => commit(app.exe)}
                                        className={
                                            "flex cursor-default flex-col items-start px-3 py-1.5 text-start outline-hidden hover:bg-nb-gray-900 focus-visible:bg-nb-gray-900"
                                        }
                                    >
                                        <span
                                            className={
                                                "max-w-full truncate text-[0.81rem] font-medium text-nb-gray-100"
                                            }
                                        >
                                            {app.name}
                                        </span>
                                        <span
                                            dir={"ltr"}
                                            className={
                                                "max-w-full truncate font-mono text-xs text-nb-gray-400"
                                            }
                                        >
                                            {app.path}
                                        </span>
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>

                    <div>
                        <Label as={"div"}>{t("apps.split.selected")}</Label>
                        {settings.apps.length === 0 ? (
                            <EmptyState
                                icon={AppWindowIcon}
                                title={t("apps.split.empty")}
                                className={"relative top-[-3.8rem]"}
                            />
                        ) : (
                            <ul className={"flex flex-col gap-1"}>
                                {visibleApps.map((exe) => (
                                    <AppRow
                                        key={exe}
                                        exe={exe}
                                        name={nameByExe.get(exe) ?? exe}
                                        onRemove={removeApp}
                                    />
                                ))}
                            </ul>
                        )}
                    </div>

                    <div className={"flex items-center justify-end gap-3"}>
                        {error ? (
                            <HelpText margin={false} className={"text-red-500"}>
                                {error}
                            </HelpText>
                        ) : applying ? (
                            <span className={"text-xs text-nb-gray-300"}>
                                {t("apps.split.reconnecting")}
                            </span>
                        ) : null}
                        <Button
                            variant={"primary"}
                            size={"md"}
                            disabled={!hasChanges || loading}
                            loading={applying}
                            onClick={() => save()}
                        >
                            {t("apps.split.apply")}
                        </Button>
                    </div>
                </>
            )}
        </SectionGroup>
    );
}

const AppRow = ({
    exe,
    name,
    onRemove,
}: {
    exe: string;
    name: string;
    onRemove: (exe: string) => void;
}) => {
    const { t } = useTranslation();
    return (
        <li
            className={
                "flex items-center gap-3 rounded-md border border-nb-gray-850 bg-nb-gray-920 px-3 py-2"
            }
        >
            <div className={"flex min-w-0 flex-1 flex-col leading-tight"}>
                <TruncatedText
                    text={name}
                    className={
                        "block max-w-[300px] truncate text-[0.81rem] font-medium text-nb-gray-100"
                    }
                />
                <TruncatedText
                    text={exe}
                    dir={"ltr"}
                    className={"block max-w-[300px] truncate font-mono text-xs text-nb-gray-400"}
                />
            </div>
            <IconButton
                icon={XIcon}
                iconSize={14}
                aria-label={t("apps.split.remove", { name })}
                onClick={() => onRemove(exe)}
                className={"h-8 w-8 shrink-0"}
            />
        </li>
    );
};
