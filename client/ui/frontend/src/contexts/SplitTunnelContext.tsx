import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useMemo,
    useState,
    type ReactNode,
} from "react";
import { SplitTunnel as SplitTunnelSvc } from "@bindings/services";
import type { RunningApp } from "@bindings/services/models.js";

export type SplitTunnelMode = "off" | "include" | "exclude";

// The generated bindings type mode as a plain string (the daemon owns the
// values); narrow it once at the load boundary so the rest of the UI gets the
// union. Anything unexpected degrades to "off" rather than a broken selector.
type LocalSettings = { mode: SplitTunnelMode; apps: string[] };

const normalizeMode = (raw: string): SplitTunnelMode =>
    raw === "include" || raw === "exclude" ? raw : "off";

type SplitTunnelContextValue = {
    loading: boolean;
    applying: boolean;
    settings: LocalSettings | null;
    runningApps: RunningApp[];
    error: string | null;
    addApp: (exe: string) => void;
    removeApp: (exe: string) => void;
    setMode: (mode: SplitTunnelMode) => void;
    hasChanges: boolean;
    save: () => Promise<void>;
};

const SplitTunnelContext = createContext<SplitTunnelContextValue | null>(null);

export const useSplitTunnel = () => {
    const ctx = useContext(SplitTunnelContext);
    if (!ctx) {
        throw new Error("useSplitTunnel must be used inside SplitTunnelProvider");
    }
    return ctx;
};

// The daemon identifies apps by lowercased executable basenames; normalize
// locally so a hand-typed entry compares equal to its daemon-side twin.
const normalizeAppId = (exe: string): string => exe.trim().toLowerCase();

const sameApps = (a: string[], b: string[]): boolean => {
    if (a.length !== b.length) return false;
    const sa = [...a].sort();
    const sb = [...b].sort();
    return sa.every((v, i) => v === sb[i]);
};

export const SplitTunnelProvider = ({ children }: { children: ReactNode }) => {
    const [loading, setLoading] = useState(true);
    const [applying, setApplying] = useState(false);
    const [settings, setSettings] = useState<LocalSettings | null>(null);
    // Last copy confirmed by the daemon; hasChanges is measured against it.
    const [saved, setSaved] = useState<LocalSettings | null>(null);
    const [runningApps, setRunningApps] = useState<RunningApp[]>([]);
    const [error, setError] = useState<string | null>(null);

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const [s, apps] = await Promise.all([
                SplitTunnelSvc.Get(),
                SplitTunnelSvc.RunningApps(),
            ]);
            const local: LocalSettings = s
                ? { mode: normalizeMode(s.mode), apps: s.apps }
                : { mode: "off", apps: [] };
            setSettings(local);
            setSaved(local);
            setRunningApps(apps);
            setError(null);
        } catch (e) {
            console.error("[SplitTunnelContext] load failed", e);
            setError(String(e));
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        load().catch((err: unknown) => console.error("[SplitTunnelContext] load failed", err));
    }, [load]);

    // addApp/removeApp/setMode edit the local copy only; save() persists it.
    const addApp = useCallback((exe: string) => {
        const id = normalizeAppId(exe);
        if (!id) return;
        setSettings((prev) => {
            if (!prev || prev.apps.includes(id)) return prev;
            return { ...prev, apps: [...prev.apps, id].sort() };
        });
    }, []);

    const removeApp = useCallback((exe: string) => {
        setSettings((prev) =>
            prev ? { ...prev, apps: prev.apps.filter((a) => a !== exe) } : prev,
        );
    }, []);

    const setMode = useCallback((mode: SplitTunnelMode) => {
        setSettings((prev) => (prev ? { ...prev, mode } : prev));
    }, []);

    const hasChanges = useMemo(
        () =>
            !!settings &&
            !!saved &&
            (settings.mode !== saved.mode || !sameApps(settings.apps, saved.apps)),
        [settings, saved],
    );

    const save = useCallback(async () => {
        if (!settings || !hasChanges) return;
        setApplying(true);
        try {
            await SplitTunnelSvc.Set({ mode: settings.mode, apps: settings.apps });
            // Apply reconnects the tunnel (Down + Up); StatusContext picks the
            // new connection state up on its own.
            await SplitTunnelSvc.Apply();
            await load();
        } catch (e) {
            console.error("[SplitTunnelContext] save failed", e);
            setError(String(e));
        } finally {
            setApplying(false);
        }
    }, [settings, hasChanges, load]);

    const value = useMemo<SplitTunnelContextValue>(
        () => ({
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
        }),
        [
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
        ],
    );

    return <SplitTunnelContext.Provider value={value}>{children}</SplitTunnelContext.Provider>;
};
