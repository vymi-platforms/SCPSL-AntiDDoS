using AntiDDoS.Patches.AntiSpoofing;
using HarmonyLib;
using LabApi.Features.Console;
using Mirror;
using System.Collections.Concurrent;

namespace AntiDDoS.Patches;

internal class SecureNetThreading {
    private const int MaxLogsPerSecond = 5;
    private const int MaxQueuedSends = 65536;

    private readonly struct PendingSend {
        public readonly NetworkConnection Connection;
        public readonly byte[] Buffer;
        public readonly int ChannelId;

        public PendingSend(NetworkConnection connection, byte[] buffer, int channelId) {
            this.Connection = connection;
            this.Buffer = buffer;
            this.ChannelId = channelId;
        }
    }

    private static readonly ConcurrentQueue<PendingSend> _pendingSends = new();
    private static int _pendingCount;
    private static long _marshalTotal;

    public static long MarshalTotal => Interlocked.Read(ref _marshalTotal);

    private static readonly object LogGate = new();
    private static long _logSecond = -1;
    private static int _loggedThisSecond;
    private static int _suppressedThisSecond;

    private static int _mainThreadId;
    [ThreadStatic]
    private static bool _isPumping;

    public static void InitializeMainThread() {
        _mainThreadId = Thread.CurrentThread.ManagedThreadId;
    }

    public static bool IsMainThread() {
        int mainId = Volatile.Read(ref _mainThreadId);
        if (mainId != 0)
            return Thread.CurrentThread.ManagedThreadId == mainId;

        if (ThreadLog.mainThreadId != 0 && ThreadLog.IsMainThread())
            return true;

        return true;
    }

    [HarmonyPatch(typeof(NetworkWriterPool), nameof(NetworkWriterPool.Get))]
    internal class NetworkWriterPoolGet {
        private static void Prefix() => WarnUnsafe("NetworkWriterPool.Get", false);
    }

    [HarmonyPatch(typeof(NetworkWriterPool), nameof(NetworkWriterPool.Return))]
    internal class NetworkWriterPoolReturn {
        private static void Prefix() => WarnUnsafe("NetworkWriterPool.Return", false);
    }

    [HarmonyPatch(typeof(NetworkConnection), nameof(NetworkConnection.Send), new[] { typeof(ArraySegment<byte>), typeof(int) })]
    internal class NetworkConnectionSend {
        private static bool Prefix(NetworkConnection __instance, ArraySegment<byte> segment, int channelId) {
            if (_isPumping || IsMainThread())
                return true;

            MarshalSend(__instance, segment, channelId);
            return false;
        }
    }

    [HarmonyPatch(typeof(CustomNetworkManager), nameof(CustomNetworkManager.FixedUpdate))]
    internal class MainThreadPump {
        private static void Postfix() {
            if (_mainThreadId == 0)
                _mainThreadId = Thread.CurrentThread.ManagedThreadId;

            Pump();
        }
    }

    private static void MarshalSend(NetworkConnection connection, ArraySegment<byte> segment, int channelId) {
        if (Volatile.Read(ref _pendingCount) >= MaxQueuedSends) {
            WarnUnsafe("NetworkConnection.Send (marshal queue full, send dropped)", false);
            return;
        }

        byte[] buffer = new byte[segment.Count];
        if (segment.Count > 0)
            Array.Copy(segment.Array!, segment.Offset, buffer, 0, segment.Count);

        Interlocked.Increment(ref _pendingCount);
        _pendingSends.Enqueue(new PendingSend(connection, buffer, channelId));
        Interlocked.Increment(ref _marshalTotal);

        WarnUnsafe("NetworkConnection.Send (auto-marshaled to main thread)", true);
    }

    public static void Pump() {
        if (Volatile.Read(ref _pendingCount) == 0)
            return;

        _isPumping = true;
        try {
            while (_pendingSends.TryDequeue(out PendingSend item)) {
                Interlocked.Decrement(ref _pendingCount);

                try {
                    item.Connection?.Send(new ArraySegment<byte>(item.Buffer), item.ChannelId);
                }
                catch (Exception) {
                }
            }
        }
        finally {
            _isPumping = false;
        }
    }

    private static void WarnUnsafe(string methodName, bool marshaled) {
        if (IsMainThread())
            return;

        long second = FastClock.UnixSeconds();
        bool log;
        int suppressed;

        lock (LogGate) {
            if (second != _logSecond) {
                _logSecond = second;
                _loggedThisSecond = 0;
                _suppressedThisSecond = 0;
            }

            log = _loggedThisSecond < MaxLogsPerSecond;
            if (log)
                _loggedThisSecond++;
            else
                _suppressedThisSecond++;

            suppressed = _suppressedThisSecond;
        }

        if (log) {
            string suppressedNote = suppressed > 0
                ? $"(+{suppressed} similar violations suppressed in the last second)\n"
                : string.Empty;

            if (marshaled) {
                Logger.Warn($"[THREAD MARSHAL] {methodName} called from a background thread.\n" +
                            $"The send was safely queued and will be flushed on the next main thread tick.\n{suppressedNote}");
            }
            else {
                string cleanStack = string.Join("\n", Environment.StackTrace.
                    Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Where(line => !line.Contains(nameof(SecureNetThreading)) && !line.Contains("System.Environment")));

                Logger.Error($"\n[CRITICAL THREAD VIOLATION] Detected access to {methodName} from background thread!\n" +
                             $"This causes local NetworkClient crash.\n" +
                             $"STACK TRACE:\n{cleanStack}\n{suppressedNote}");
            }
        }
    }
}
