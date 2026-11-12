import { type KeyboardEvent, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { AppWindowIcon, XIcon } from "lucide-react";
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

const MAX_MATCHES = 10;

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
    const inputRef = useRef<HTMLInputElement>(null);

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

    // Live matches from the running apps, filtered by the typed text; apps
    // already in the list stay out of the dropdown.
    const matches = useMemo(() => {
        const q = query.trim().toLowerCase();
        if (!q) return [];
        return runningApps
            .filter(
                (app) =>
                    !added.has(app.exe) &&
                    (app.name.toLowerCase().includes(q) ||
                        app.exe.toLowerCase().includes(q) ||
                        app.path.toLowerCase().includes(q)),
            )
            .slice(0, MAX_MATCHES);
    }, [query, runningApps, added]);

    const commit = (exe: string) => {
        addApp(exe);
        setQuery("");
        inputRef.current?.focus();
    };

    // Enter picks the first match; with nothing matching, the typed text
    // itself becomes the app id (the daemon normalizes it).
    const onSearchKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
        if (e.key !== "Enter") return;
        e.preventDefault();
        commit(matches.length > 0 ? matches[0].exe : query);
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
                        <div
                            className={
                                "flex items-center rounded-md border border-nb-gray-850 bg-nb-gray-920 focus-within:border-nb-gray-700"
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
                                {settings.apps.map((exe) => (
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
