using AntiDDoS.Patches.Compat;
using HarmonyLib;
using LabApi.Features.Console;
using System;
using System.Reflection;

namespace AntiDDoS.Patches.Transport
{
    internal static class TransportLimits
    {
        private const int MaxReliableMessageSize = 65535;

        public static void Apply(Harmony harmony)
        {
            try
            {
                Type? type = PatchUtil.FindType("LiteNetLib4MirrorCore");
                if (type == null)
                {
                    Logger.Warn("[AntiDDoS] 0014: LiteNetLib4MirrorCore not found, skipped");
                    return;
                }

                MethodInfo? method = PatchUtil.MethodInHierarchy(type, "GetMaxPacketSize");
                if (method == null)
                {
                    Logger.Warn("[AntiDDoS] 0014: LiteNetLib4MirrorCore.GetMaxPacketSize not found, skipped");
                    return;
                }

                PatchUtil.SafePatch(harmony, method, "0014: realistic max message size (<=64KB)",
                    null, new HarmonyMethod(AccessTools.Method(typeof(TransportLimits), nameof(MaxSizePostfix))));
            }
            catch (Exception e)
            {
                Logger.Warn($"[AntiDDoS] 0014: patch failed: {e.Message}");
            }
        }

        private static void MaxSizePostfix(ref int __result)
        {
            if (__result > MaxReliableMessageSize)
                __result = MaxReliableMessageSize;
        }
    }
}
