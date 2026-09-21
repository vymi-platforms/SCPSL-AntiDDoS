using AntiDDoS.Patches.Compat;
using AntiDDoS.Tokens;
using HarmonyLib;
using LabApi.Features.Console;
using Mirror;
using System.Reflection;

namespace AntiDDoS.Patches.Gameplay;

internal static class SubroutineGuard {
    private static readonly TokenBuckets<NetworkConnectionToClient> _triggerBuckets = new(40, 20);
    private static readonly TokenBuckets<object> _mimicryBuckets = new(3, 2.5);

    public static void Apply(Harmony harmony) {
        PatchSubroutineTrigger(harmony);
        PatchMimicryTransmitter(harmony);
    }

    private static void PatchSubroutineTrigger(Harmony harmony) {
        try {
            Type? type = PatchUtil.FindType("PlayerRoles.Subroutines.SubroutineMessage");
            MethodInfo? method = null;

            for (Type? t = type; t != null && t != typeof(object); t = t.BaseType) {
                method = t.GetMethod("ServerApplyTrigger",
                    BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
                if (method != null)
                    break;
            }

            if (method == null) {
                Logger.Warn("[AntiDDoS] 0019: SubroutineMessage.ServerApplyTrigger not found, skipped");
                return;
            }

            PatchUtil.SafePatch(harmony, method, "0019: SubroutineMessage rate limit (20/s per connection)",
                new HarmonyMethod(AccessTools.Method(typeof(SubroutineGuard), nameof(TriggerPrefix))));
        }
        catch (Exception e) {
            Logger.Warn($"[AntiDDoS] 0019: SubroutineMessage patch failed: {e.Message}");
        }
    }

    private static bool TriggerPrefix(object[] __args) {
        foreach (object arg in __args) {
            if (arg is NetworkConnectionToClient connection)
                return _triggerBuckets.Allow(connection);
        }

        return true;
    }

    private static void PatchMimicryTransmitter(Harmony harmony) {
        try {
            Type? type = PatchUtil.FindType("PlayerRoles.PlayableScps.Scp939.Mimicry.MimicryTransmitter");
            MethodInfo? method = type?.GetMethod("ServerProcessCmd",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);

            if (method == null) {
                Logger.Warn("[AntiDDoS] 0019: MimicryTransmitter.ServerProcessCmd not found, skipped");
                return;
            }

            PatchUtil.SafePatch(harmony, method, "0019: MimicryTransmitter broadcast cooldown (2.5/s)",
                new HarmonyMethod(AccessTools.Method(typeof(SubroutineGuard), nameof(MimicryPrefix))));
        }
        catch (Exception e) {
            Logger.Warn($"[AntiDDoS] 0019: MimicryTransmitter patch failed: {e.Message}");
        }
    }

    private static bool MimicryPrefix(object __instance) => _mimicryBuckets.Allow(__instance);
}
