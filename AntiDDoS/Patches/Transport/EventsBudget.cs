using AntiDDoS.Patches.Compat;
using HarmonyLib;
using LabApi.Features.Console;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;

namespace AntiDDoS.Patches.Transport;

internal static class EventsBudget {
    // Increase budget from 5ms to 30ms so that voice and gameplay network events
    // are never starved or delayed during multi-player traffic, while still protecting
    // the server against infinite hang/crash loops.
    private static readonly long BudgetTicks = Stopwatch.Frequency * 50 / 1000;
    private const int MaxActionsPerFrame = 5000;

    private static MemberInfo? _eventsMember;
    private static MemberInfo? _pollingMember;

    public static void Apply(Harmony harmony) {
        try {
            Type? transportType = PatchUtil.FindType("LiteNetLib4MirrorTransport");
            if (transportType == null) {
                Logger.Warn("[AntiDDoS] 0015: LiteNetLib4MirrorTransport not found, skipped");
                return;
            }

            _eventsMember = (MemberInfo?)PatchUtil.FieldInHierarchy(transportType, "Events") ??
                            PatchUtil.PropertyInHierarchy(transportType, "Events");
            _pollingMember = (MemberInfo?)PatchUtil.FieldInHierarchy(transportType, "Polling") ??
                             PatchUtil.PropertyInHierarchy(transportType, "Polling");

            MethodInfo? lateUpdate = PatchUtil.MethodInHierarchy(transportType, "LateUpdate");

            if (_eventsMember == null || lateUpdate == null) {
                Logger.Warn("[AntiDDoS] 0015: LateUpdate/Events not resolved, skipped (fail-open)");
                return;
            }

            if (_pollingMember == null) {
                Logger.Warn("[AntiDDoS] 0015: Polling not resolved, skipped (fail-open)");
                return;
            }

            PatchUtil.SafePatch(harmony, lateUpdate, "0015: budgeted + exception-isolated event pump (30ms/frame)",
                new HarmonyMethod(AccessTools.Method(typeof(EventsBudget), nameof(PumpPrefix))));
        }
        catch (Exception e) {
            Logger.Warn($"[AntiDDoS] 0015: patch failed: {e.Message}");
        }
    }

    private static bool PumpPrefix(object __instance) {
        if (!ReadBool(_pollingMember, __instance))
            return false;

        if (_eventsMember == null)
            return false;

        object? raw;
        if (_eventsMember is FieldInfo field)
            raw = field.GetValue(field.IsStatic ? null : __instance);
        else if (_eventsMember is PropertyInfo prop)
            raw = prop.GetValue(prop.GetGetMethod(true)?.IsStatic == true ? null : __instance, null);
        else
            return false;

        if (raw is not ConcurrentQueue<Action> queue)
            return false;

        long start = Stopwatch.GetTimestamp();
        int errors = 0;
        int count = 0;

        while (count < MaxActionsPerFrame &&
               (count < 500 || Stopwatch.GetTimestamp() - start < BudgetTicks) &&
               queue.TryDequeue(out Action action)) {
            count++;
            try {
                action();
            }
            catch (Exception e) {
                errors++;
                if (errors == 1 || errors % 100 == 0)
                    Logger.Warn($"[AntiDDoS] 0015: network event handler exception (count={errors}): {e.Message}");
            }
        }

        return false;
    }

    private static bool IsStatic(MemberInfo? member) =>
        member is FieldInfo f ? f.IsStatic : (member is PropertyInfo p && (p.GetGetMethod(true)?.IsStatic ?? false));

    private static bool ReadBool(MemberInfo? member, object instance) {
        if (member == null)
            return false;

        try {
            object? value = member is FieldInfo field
                ? field.GetValue(field.IsStatic ? null : instance)
                : (member is PropertyInfo prop ? prop.GetValue(prop.GetGetMethod(true)?.IsStatic == true ? null : instance, null) : null);
            return value is bool b && b;
        }
        catch {
            return false;
        }
    }
}
