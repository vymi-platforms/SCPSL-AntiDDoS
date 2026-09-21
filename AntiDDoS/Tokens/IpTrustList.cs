using System.Collections.Concurrent;
using System.Diagnostics;

namespace AntiDDoS.Tokens;

internal sealed class IpTrustList {
    private readonly ConcurrentDictionary<uint, long> _entries = new();
    private readonly long _ttlSeconds;

    public IpTrustList(long ttlSeconds) => this._ttlSeconds = ttlSeconds;

    public long Count => this._entries.Count;

    public bool IsTrusted(uint ip, long nowSeconds) {
        if (!this._entries.TryGetValue(ip, out long expiry))
            return false;

        if (nowSeconds > expiry) {
            ((ICollection<KeyValuePair<uint, long>>)this._entries).Remove(new KeyValuePair<uint, long>(ip, expiry));
            return false;
        }

        if (expiry - nowSeconds < this._ttlSeconds - 60) {
            this._entries[ip] = nowSeconds + this._ttlSeconds;
        }

        return true;
    }

    public void Trust(uint ip, long nowSeconds) =>
        this._entries[ip] = nowSeconds + this._ttlSeconds;

    public void Prune(long nowSeconds) {
        foreach (KeyValuePair<uint, long> kv in this._entries) {
            if (nowSeconds > kv.Value)
                ((ICollection<KeyValuePair<uint, long>>)this._entries).Remove(kv);
        }
    }
}

internal sealed class IpRateLimiter {
    private readonly ConcurrentDictionary<uint, long> _slots = new();
    private readonly long _intervalTicks;
    private long _nextPrune;

    public IpRateLimiter(int minIntervalMs) =>
        this._intervalTicks = Math.Max(1, Stopwatch.Frequency * minIntervalMs / 1000);

    public bool Allow(uint ip) {
        long now = Stopwatch.GetTimestamp();
        this.Prune(now);

        while (true) {
            if (this._slots.TryGetValue(ip, out long last)) {
                if (now - last < this._intervalTicks)
                    return false;

                if (this._slots.TryUpdate(ip, now, last))
                    return true;

                continue;
            }

            if (this._slots.TryAdd(ip, now))
                return true;
        }
    }

    public void Prune() => this.Prune(Stopwatch.GetTimestamp());

    private void Prune(long now) {
        long next = Volatile.Read(ref this._nextPrune);
        if (now < next)
            return;

        if (Interlocked.CompareExchange(ref this._nextPrune, now + Stopwatch.Frequency, next) != next)
            return;

        foreach (KeyValuePair<uint, long> kv in this._slots) {
            if (now - kv.Value >= this._intervalTicks)
                ((ICollection<KeyValuePair<uint, long>>)this._slots).Remove(kv);
        }
    }
}
