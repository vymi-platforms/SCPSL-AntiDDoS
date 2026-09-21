using HarmonyLib;
using UnityEngine;

using Logger = LabApi.Features.Console.Logger;

namespace AntiDDoS.Patches.AntiSpoofing;

[HarmonyPatch(typeof(CustomNetworkManager), nameof(CustomNetworkManager.FixedUpdate))]
internal class PreAuthLogger {
    public static uint Processed;
    public static long ProcessedTotal;

    private static float _time;

    private static void Prefix() {
        _time += Time.fixedUnscaledDeltaTime;
        if (_time < 10)
            return;

        _time = 0;

        CheckBeforeConnection.Prune();
        WriteStats();

        if (Processed == 0)
            return;

        string message = string.Format("Anti-Spoofing processed {0} connection[s] within the last 10 seconds.", Processed);
        if (Processed > 10000)
            Logger.Raw(message, ConsoleColor.Red);
        else if (Processed > 100)
            Logger.Raw(message, ConsoleColor.Yellow);
        else
            Logger.Raw(message, ConsoleColor.Gray);

        Processed = 0;
    }

    private static void WriteStats() {
        try {
            string path = Environment.GetEnvironmentVariable("ANTIDDOOS_STATS_PATH") ?? "antiddos-stats.json";
            string json = string.Format(
                "{{\"ts\":{0},\"preauth_processed_total\":{1},\"preauth_processed_window\":{2},\"whitelist_ips\":{3}," +
                "\"challenge_sent_total\":{4},\"validated_total\":{5},\"seq_total\":{6},\"thread_marshal_total\":{7}}}",
                FastClock.UnixSeconds(),
                Interlocked.Read(ref ProcessedTotal),
                Processed,
                CheckBeforeConnection.WhitelistCount,
                Interlocked.Read(ref CheckBeforeConnection.ChallengeSentTotal),
                Interlocked.Read(ref CheckBeforeConnection.ValidatedTotal),
                Interlocked.Read(ref CheckBeforeConnection.SeqTotal),
                SecureNetThreading.MarshalTotal);

            System.IO.File.WriteAllText(path, json);
        }
        catch {
        }
    }
}