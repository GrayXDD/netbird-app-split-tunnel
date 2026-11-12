import { type KeyboardEvent, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import Skeleton from "react-loading-skeleton";
import { AppWindowIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { SplitTunnel as SplitTunnelSvc } from "@bindings/services";
import { Button } from "@/components/buttons/Button";
import { IconButton } from "@/components/buttons/IconButton";
import { EmptyState } from "@/components/empty-state/EmptyState";
import { NoResults } from "@/components/empty-state/NoResults";
import { SearchInput } from "@/components/inputs/SearchInput";
import { Select, type SelectOption } from "@/components/inputs/Select";
import { ToggleSwitch } from "@/components/switches/ToggleSwitch";
import { TruncatedText } from "@/components/TruncatedText";
import { HelpText } from "@/components/typography/HelpText";
import { Label } from "@/components/typography/Label";
import { useSplitTunnel, type SplitTunnelMode } from "@/contexts/SplitTunnelContext";
import { cn } from "@/lib/cn";
import { useDirection } from "@/hooks/useDirection";

const MAX_MATCHES = 10;
const DUPLICATE_WARNING_MS = 2000;

// Modes reachable from the mode selector; "off" lives only in the header toggle.
type ActiveMode = Exclude<SplitTunnelMode, "off">;

// basename of a native path, tolerating both separators (the dialog returns
// platform paths; the web view may run on another OS).
const basename = (path: string): string => path.split(/[\\/]+/).pop() ?? path;

export const SplitTunnelPanel = () => {
    const dir = useDirection();
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

    // The header toggle stores only on/off: it remembers the last active mode
    // and restores it when the feature is switched back on.
    const [lastMode, setLastMode] = useState<ActiveMode>("include");
    const [search, setSearch] = useState("");
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

    const isEnabled = !!settings && settings.mode !== "off";

    const onToggle = (next: boolean) => {
        if (!settings || next === isEnabled) return;
        if (next) {
            setMode(lastMode);
        } else {
            if (settings.mode === "include" || settings.mode === "exclude") {
                setLastMode(settings.mode);
            }
            setMode("off");
        }
    };

    const modeOptions = useMemo<SelectOption<SplitTunnelMode>[]>(
        () => [
            { value: "include", label: t("apps.split.mode.include") },
            { value: "exclude", label: t("apps.split.mode.exclude") },
        ],
        [t],
    );

    // While off the selector shows the remembered mode; picking a mode then
    // only updates the memory — the toggle turns the feature on with it.
    const modeValue: SplitTunnelMode =
        settings && settings.mode !== "off" ? settings.mode : lastMode;

    const onSelectMode = (mode: SplitTunnelMode) => {
        if (mode !== "include" && mode !== "exclude") return;
        setLastMode(mode);
        if (settings && settings.mode !== "off") setMode(mode);
    };

    const nameByExe = useMemo(
        () => new Map(runningApps.map((app) => [app.exe, app.name])),
        [runningApps],
    );

    const added = useMemo(() => new Set(settings?.apps ?? []), [settings]);

    const normalizedSearch = useMemo(() => search.trim().toLowerCase(), [search]);

    // Sorted by display name (the exe id when the app is not running).
    const visibleApps = useMemo(() => {
        const apps = [...(settings?.apps ?? [])];
        apps.sort((a, b) => (nameByExe.get(a) ?? a).localeCompare(nameByExe.get(b) ?? b));
        if (!normalizedSearch) return apps;
        return apps.filter(
            (exe) =>
                exe.includes(normalizedSearch) ||
                (nameByExe.get(exe) ?? "").toLowerCase().includes(normalizedSearch),
        );
    }, [settings, normalizedSearch, nameByExe]);

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
            console.error("[SplitTunnelPanel] pick executable failed", e);
        }
    };

    if (!settings) {
        return (
            <div className={"flex h-full min-h-0 flex-col px-6 py-6"}>
                {error ? (
                    <HelpText margin={false} className={"text-red-500"}>
                        {error}
                    </HelpText>
                ) : (
                    <div className={"flex flex-col gap-5"}>
                        <Skeleton width={200} height={20} />
                        <Skeleton width={360} height={14} />
                        <Skeleton width={160} height={40} />
                        <Skeleton count={3} height={38} />
                    </div>
                )}
            </div>
        );
    }

    return (
        <div className={"flex h-full min-h-0 w-full flex-col"}>
            <div className={"flex flex-col gap-4 border-b border-nb-gray-910 px-6 py-4"}>
                <div className={"flex items-center justify-between gap-6"}>
                    <div className={"min-w-0 flex-1"}>
                        <h2 className={"mb-1 text-sm font-semibold text-nb-gray-100"}>
                            {t("apps.split.title")}
                        </h2>
                        <HelpText margin={false}>{t("apps.split.description")}</HelpText>
                    </div>
                    <ToggleSwitch
                        checked={isEnabled}
                        onCheckedChange={onToggle}
                        aria-label={t("apps.split.title")}
                        className={"shrink-0"}
                    />
                </div>
                <div className={"flex items-center justify-between gap-6"}>
                    <Label as={"div"}>{t("apps.split.mode.label")}</Label>
                    <div className={"shrink-0"}>
                        <Select
                            value={modeValue}
                            options={modeOptions}
                            onChange={onSelectMode}
                            ariaLabel={t("apps.split.mode.label")}
                        />
                    </div>
                </div>
            </div>

            <div className={"flex items-center gap-2 border-b border-nb-gray-910 px-6 py-2.5"}>
                <div className={"min-w-0 flex-1"}>
                    <SearchInput
                        placeholder={t("apps.split.search.placeholder")}
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                </div>
            </div>

            {settings.apps.length === 0 ? (
                <EmptyState
                    icon={AppWindowIcon}
                    title={t("apps.split.empty")}
                    className={"relative top-[-3.8rem]"}
                />
            ) : visibleApps.length === 0 ? (
                <NoResults />
            ) : (
                <ScrollArea.Root
                    dir={dir}
                    type={"auto"}
                    className={"min-h-0 flex-1 overflow-hidden"}
                >
                    <ScrollArea.Viewport className={"h-full w-full"}>
                        <ul className={"flex flex-col py-1"}>
                            {visibleApps.map((exe) => (
                                <AppRow
                                    key={exe}
                                    exe={exe}
                                    name={nameByExe.get(exe) ?? exe}
                                    onRemove={removeApp}
                                />
                            ))}
                        </ul>
                    </ScrollArea.Viewport>
                    <ScrollArea.Scrollbar
                        orientation={"vertical"}
                        className={cn(
                            "flex touch-none transition-colors select-none",
                            "w-1.5 bg-transparent py-1",
                        )}
                    >
                        <ScrollArea.Thumb
                            className={
                                "relative flex-1 rounded-full bg-nb-gray-800 hover:bg-nb-gray-700"
                            }
                        />
                    </ScrollArea.Scrollbar>
                </ScrollArea.Root>
            )}

            <div className={"flex flex-col gap-3 border-t border-nb-gray-910 px-6 py-3.5"}>
                <div className={"relative"}>
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
                                "absolute inset-x-0 bottom-full z-10 mb-1 flex flex-col rounded-md border border-nb-gray-850 bg-nb-gray-920 py-1 shadow-lg"
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
            </div>
        </div>
    );
};

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
                "group flex items-center gap-3 border-b border-nb-gray-910/60 px-6 py-2 last:border-b-0 hover:bg-nb-gray-900/40"
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
                icon={Trash2Icon}
                iconSize={14}
                aria-label={t("apps.split.remove", { name })}
                onClick={() => onRemove(exe)}
                className={"h-8 w-8 shrink-0"}
            />
        </li>
    );
};
