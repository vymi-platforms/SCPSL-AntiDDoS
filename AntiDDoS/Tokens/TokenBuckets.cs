using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace AntiDDoS.Tokens;

internal sealed class TokenBuckets<TKey> where TKey : class {
    private sealed class Bucket {
        public double Tokens;
        public long Last;
        public readonly object Gate = new();
    }

    private readonly ConditionalWeakTable<TKey, Bucket> _buckets = new();
    private readonly double _capacity;
    private readonly double _refillPerSecond;

    public TokenBuckets(double capacity, double refillPerSecond) {
        this._capacity = Math.Max(1, capacity);
        this._refillPerSecond = Math.Max(0.01, refillPerSecond);
    }

    public bool Allow(TKey key) {
        if (key == null)
            return true;

        Bucket bucket = this._buckets.GetOrCreateValue(key);
        long now = Stopwatch.GetTimestamp();

        lock (bucket.Gate) {
            if (bucket.Last == 0) {
                bucket.Tokens = this._capacity;
                bucket.Last = now;
            }
            else {
                double elapsed = (now - bucket.Last) / (double)Stopwatch.Frequency;
                if (elapsed > 0) {
                    bucket.Tokens = Math.Min(this._capacity, bucket.Tokens + elapsed * this._refillPerSecond);
                    bucket.Last = now;
                }
            }

            if (bucket.Tokens >= 1) {
                bucket.Tokens -= 1;
                return true;
            }
        }

        return false;
    }

    public void Release(TKey key) {
        if (key != null)
            this._buckets.Remove(key);
    }
}
