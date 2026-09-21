using AntiDDoS.Patches.Compat;
using AntiDDoS.Tokens;
using HarmonyLib;
using LabApi.Features.Console;
using Mirror;
using System.Reflection;

namespace AntiDDoS.Patches.Gameplay {
    internal static class VoiceGuard {
        private const int MaxVoiceDataLength = 1024;

        // SCP:SL voice transmits ~50 Opus frames/sec.
        // Network batching and jitter can cause frames to arrive in clumps.
        // We set burst capacity to 150 and refill to 100/s to never drop legitimate voice frames,
        // while still preventing 500+ msg/s voice crasher/flooder exploits.
        private static readonly TokenBuckets<NetworkConnectionToClient> _buckets = new(150, 100);

        public static void Apply(Harmony harmony) {
            try {
                Type? type = PatchUtil.FindType("VoiceChat.Networking.VoiceTransceiver") ??
                            PatchUtil.FindType("VoiceTransceiver");

                if (type == null) {
                    Logger.Warn("[AntiDDoS] 0021: VoiceTransceiver not found, skipped");
                    return;
                }

                MethodInfo? method = PatchUtil.MethodInHierarchy(type, "ServerReceiveMessage");
                if (method == null) {
                    Logger.Warn("[AntiDDoS] 0021: VoiceTransceiver.ServerReceiveMessage not found, skipped");
                    return;
                }

                PatchUtil.SafePatch(harmony, method, "0021: voice relay rate limit (100/s, burst 150) + payload cap (1024B)",
                    new HarmonyMethod(AccessTools.Method(typeof(VoiceGuard), nameof(VoicePrefix))));
            }
            catch (Exception e) {
                Logger.Warn($"[AntiDDoS] 0021: patch failed: {e.Message}");
            }
        }

        private static bool VoicePrefix(NetworkConnection conn, VoiceChat.Networking.VoiceMessage msg) {
            if (msg.DataLength > MaxVoiceDataLength)
                return false;

            if (msg.Speaker != null && AFK.AFKManager.AFKTimers != null && AFK.AFKManager.AFKTimers.TryGetValue(msg.Speaker, out System.Diagnostics.Stopwatch? sw) && sw != null) {
                sw.Restart();
            }

            if (conn is NetworkConnectionToClient connection)
                return _buckets.Allow(connection);

            return true;
        }
    }
}
