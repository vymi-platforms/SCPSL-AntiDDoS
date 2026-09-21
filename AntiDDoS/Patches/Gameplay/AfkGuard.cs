using AntiDDoS.Patches.Compat;
using HarmonyLib;
using LabApi.Features.Console;
using Mirror;
using System.Reflection;

namespace AntiDDoS.Patches.Gameplay;

internal static class AfkGuard {
    public static void Apply(Harmony harmony) {
        // Immediately disable Mirror's inactivity timeout so idle/afk players aren't silently disconnected
        NetworkServer.disconnectInactiveConnections = false;

        PatchSetupServer(harmony);
        PatchAfkManagerUpdate(harmony);
        PatchAfkKick(harmony);
    }

    private static void PatchSetupServer(Harmony harmony) {
        try {
            Type? type = PatchUtil.FindType("CustomNetworkManager");
            MethodInfo? method = type?.GetMethod("SetupServer",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);

            if (method == null) {
                Logger.Warn("[AntiDDoS] AfkGuard: CustomNetworkManager.SetupServer not found, skipped");
                return;
            }

            PatchUtil.SafePatch(harmony, method, "disable Mirror inactivity disconnect on server setup",
                postfix: new HarmonyMethod(AccessTools.Method(typeof(AfkGuard), nameof(SetupServerPostfix))));
        }
        catch (Exception e) {
            Logger.Warn($"[AntiDDoS] AfkGuard: SetupServer patch failed: {e.Message}");
        }
    }

    private static void SetupServerPostfix() {
        NetworkServer.disconnectInactiveConnections = false;
    }

    private static void PatchAfkManagerUpdate(Harmony harmony) {
        try {
            Type? type = PatchUtil.FindType("AFK.AFKManager");
            MethodInfo? method = type?.GetMethod("OnUpdate",
                BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);

            if (method == null) {
                Logger.Warn("[AntiDDoS] AfkGuard: AFKManager.OnUpdate not found, skipped");
                return;
            }

            PatchUtil.SafePatch(harmony, method, "respect disabled AFK timer in AFKManager",
                new HarmonyMethod(AccessTools.Method(typeof(AfkGuard), nameof(AfkUpdatePrefix))));
        }
        catch (Exception e) {
            Logger.Warn($"[AntiDDoS] AfkGuard: AFKManager.OnUpdate patch failed: {e.Message}");
        }
    }

    private static bool AfkUpdatePrefix() {
        // If afk_time <= 0, do not run the AFK check loop at all
        return AFK.AFKManager._kickTime > 0f;
    }

    private static void PatchAfkKick(Harmony harmony) {
        try {
            Type? type = PatchUtil.FindType("BanPlayer");
            if (type == null) return;

            foreach (MethodInfo m in type.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)) {
                if (m.Name != "KickUser") continue;
                ParameterInfo[] pars = m.GetParameters();
                if (pars.Length >= 2 && pars[pars.Length - 1].ParameterType == typeof(string)) {
                    PatchUtil.SafePatch(harmony, m, "guard AFK kick when afk_time is disabled",
                        new HarmonyMethod(AccessTools.Method(typeof(AfkGuard), nameof(KickUserPrefix))));
                }
            }
        }
        catch (Exception e) {
            Logger.Warn($"[AntiDDoS] AfkGuard: BanPlayer.KickUser patch failed: {e.Message}");
        }
    }

    private static bool KickUserPrefix(object[] __args) {
        if (__args == null || __args.Length == 0) return true;

        object lastArg = __args[__args.Length - 1];
        if (lastArg is string reason &&
            reason.IndexOf("AFK", StringComparison.OrdinalIgnoreCase) >= 0 &&
            AFK.AFKManager._kickTime <= 0f) {
            // AFK is disabled in config, suppress kick
            return false;
        }

        return true;
    }
}
