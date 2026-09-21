using System.Diagnostics;

namespace AntiDDoS.Patches.AntiSpoofing;

internal static class FastClock {
    private static readonly long TickFrequency = Stopwatch.Frequency;

    private static long _cachedSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    private static long _cachedTick = Stopwatch.GetTimestamp();

    public static long UnixSeconds() {
        long now = Stopwatch.GetTimestamp();
        if (now - Volatile.Read(ref _cachedTick) >= TickFrequency) {
            Volatile.Write(ref _cachedSeconds, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            Volatile.Write(ref _cachedTick, now);
        }

        return Volatile.Read(ref _cachedSeconds);
    }
}
