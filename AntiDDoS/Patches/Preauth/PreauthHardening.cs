using AntiDDoS.Patches.Compat;
using AntiDDoS.Tokens;
using HarmonyLib;
using LabApi.Features.Console;
using System.Collections;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Reflection;

namespace AntiDDoS.Patches.Preauth;

internal static class PreauthHardening {
    private const int MaxPendingRequests = 1024;
    private const int BanCacheMaxEntries = 10000;
    private const byte ExpectedProtocolId = 13;
    private static readonly long BanCacheTtlTicks = 5L * Stopwatch.Frequency;

    private static FieldInfo? _peersDict;
    private static MethodInfo? _tryGetPeer;
    private static FieldInfo? _requestsDict;
    private static MethodInfo? _poolRecycle;
    private static MethodInfo? _getProtocolId;
    private static byte? _peerNotFoundByte;

    private static readonly ConcurrentDictionary<string, BanCacheEntry> _banCache =
        new();

    private sealed class BanCacheEntry {
        public object? Value;
        public long Tick;
    }

    private static readonly IpRateLimiter _unconnectedLimiter = new(250);
    private static long _nextSweep;
    private static long _lastSweepLog;

    public static void Apply(Harmony harmony) {
        PatchPendingRequestCount(harmony);
        PatchBanQueryCache(harmony);
        PatchHandleMessageReceived(harmony);
        PatchRequestsDictSweep(harmony);
        PatchUnconnectedRateLimit(harmony);
    }

    private static void PatchPendingRequestCount(Harmony harmony) {
        try {
            Type? type = PatchUtil.FindType("LiteNetLib4MirrorServer");
            if (type == null) {
                Logger.Warn("[AntiDDoS] 0004: LiteNetLib4MirrorServer not found, skipped");
                return;
            }

            MethodInfo? method = PatchUtil.MethodInHierarchy(type, "GetPendingConnectionRequestsCount");
            if (method == null) {
                Logger.Warn("[AntiDDoS] 0004: LiteNetLib4MirrorServer.GetPendingConnectionRequestsCount not found, skipped");
                return;
            }

            MethodInfo prefix = method.IsStatic
                ? AccessTools.Method(typeof(PreauthHardening), nameof(ZeroCountStatic))
                : AccessTools.Method(typeof(PreauthHardening), nameof(ZeroCountInstance));

            PatchUtil.SafePatch(harmony, method, "0004: fail-closed pending-request heuristic (signature + rate-limit always enforced)",
                new HarmonyMethod(prefix));
        }
        catch (Exception e) {
            Logger.Warn($"[AntiDDoS] 0004: patch failed: {e.Message}");
        }
    }

    private static bool ZeroCountStatic(ref int __result) {
        __result = 0;
        return false;
    }

    private static bool ZeroCountInstance(object __instance, ref int __result) {
        __result = 0;
        return false;
    }

    private static void PatchBanQueryCache(Harmony harmony) {
        try {
            Type? type = PatchUtil.FindType("BanHandler");
            MethodInfo? method = type?
                .GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
                .FirstOrDefault(m => m.Name == "QueryBan" &&
                                     m.ReturnType != typeof(void) &&
                                     m.GetParameters().Length == 2 &&
                                     m.GetParameters()[0].ParameterType == typeof(string) &&
                                     m.GetParameters()[1].ParameterType == typeof(string));

            if (method == null) {
                Logger.Warn("[AntiDDoS] 0022: BanHandler.QueryBan(string, string) not found, skipped");
                return;
            }

            PatchUtil.SafePatch(harmony, method, "0022: BanHandler.QueryBan in-memory cache (5s TTL)",
                new HarmonyMethod(AccessTools.Method(typeof(PreauthHardening), nameof(QueryBanPrefix))),
                new HarmonyMethod(AccessTools.Method(typeof(PreauthHardening), nameof(QueryBanPostfix))));
        }
        catch (Exception e) {
            Logger.Warn($"[AntiDDoS] 0022: patch failed: {e.Message}");
        }
    }

    private static bool QueryBanPrefix(string? userId, string? ip, ref object? __result) {
        long now = Stopwatch.GetTimestamp();
        string key = (userId ?? string.Empty) + "\x1" + (ip ?? string.Empty);

        if (_banCache.TryGetValue(key, out BanCacheEntry? entry) && entry != null) {
            if (now - entry.Tick < BanCacheTtlTicks) {
                __result = entry.Value;
                return false;
            }

            _banCache.TryRemove(key, out _);
        }

        return true;
    }

    private static void QueryBanPostfix(string? userId, string? ip, object? __result) {
        if (_banCache.Count > BanCacheMaxEntries)
            _banCache.Clear();

        _banCache[(userId ?? string.Empty) + "\x1" + (ip ?? string.Empty)] =
            new BanCacheEntry { Value = __result, Tick = Stopwatch.GetTimestamp() };
    }

    private static void PatchHandleMessageReceived(Harmony harmony) {
        try {
            Type managerType = typeof(LiteNetLib.LiteNetManager);

            _peersDict = PatchUtil.FieldInHierarchy(managerType, "_peersDict");
            _tryGetPeer = PatchUtil.MethodInHierarchy(managerType, "TryGetPeer");
            _poolRecycle = PatchUtil.MethodInHierarchy(managerType, "PoolRecycle");
            Type? connectPacketType = PatchUtil.FindType("LiteNetLib.NetConnectRequestPacket");
            _getProtocolId = connectPacketType != null ? PatchUtil.MethodInHierarchy(connectPacketType, "GetProtocolId") : null;
            _peerNotFoundByte = PropByte("PeerNotFound");

            MethodInfo? target = PatchUtil.MethodInHierarchy(managerType, "HandleMessageReceived");
            if (target == null) {
                Logger.Warn("[AntiDDoS] 0013: HandleMessageReceived not found, skipped");
                return;
            }

            if (_peersDict == null && _tryGetPeer == null && _poolRecycle == null) {
                Logger.Warn("[AntiDDoS] 0013: _peersDict/TryGetPeer/PoolRecycle not resolved, skipped (fail-open)");
                return;
            }

            PatchUtil.SafePatch(harmony, target, "0013: silent drop of reflection-prone packets from non-peers",
                new HarmonyMethod(AccessTools.Method(typeof(PreauthHardening), nameof(HandleMessagePrefix))));
        }
        catch (Exception e) {
            Logger.Warn($"[AntiDDoS] 0013: patch failed: {e.Message}");
        }
    }

    private static bool HandleMessagePrefix(object __instance, LiteNetLib.NetPacket packet, IPEndPoint remoteEndPoint) {
        if (packet == null || remoteEndPoint == null)
            return true;

        byte prop = (byte)packet.Property;

        if (prop == (byte)LiteNetLib.PacketProperty.UnconnectedMessage) {
            if (IpUtil.IsIpv4(remoteEndPoint.Address) && !_unconnectedLimiter.Allow(IpUtil.IpKey(remoteEndPoint.Address))) {
                Recycle(__instance, packet);
                return false;
            }

            return true;
        }

        if (prop == (byte)LiteNetLib.PacketProperty.Disconnect ||
            (_peerNotFoundByte.HasValue && prop == _peerNotFoundByte.Value)) {
            if (!HasPeer(__instance, remoteEndPoint)) {
                Recycle(__instance, packet);
                return false;
            }

            return true;
        }

        if (prop == (byte)LiteNetLib.PacketProperty.ConnectRequest && _getProtocolId != null) {
            try {
                if ((int)_getProtocolId.Invoke(null, [packet]) != ExpectedProtocolId) {
                    Recycle(__instance, packet);
                    return false;
                }
            }
            catch {
            }
        }

        return true;
    }

    private static bool HasPeer(object manager, IPEndPoint endPoint) {
        if (manager is LiteNetLib.LiteNetManager lnm)
            return lnm.TryGetPeer(endPoint, out _);

        if (_tryGetPeer != null) {
            try {
                object?[] args = [endPoint, null];
                return (bool)_tryGetPeer.Invoke(manager, args);
            }
            catch {
            }
        }

        FieldInfo? peersDict = _peersDict;
        if (peersDict != null) {
            if (peersDict.GetValue(manager) is IDictionary dict)
                return dict.Contains(endPoint);
        }

        return true;
    }

    private static void Recycle(object manager, LiteNetLib.NetPacket packet) {
        try {
            _poolRecycle?.Invoke(manager, new object[] { packet });
        }
        catch {
        }
    }

    private static void PatchRequestsDictSweep(Harmony harmony) {
        try {
            Type managerType = typeof(LiteNetLib.LiteNetManager);

            _requestsDict = PatchUtil.FieldInHierarchy(managerType, "_requestsDict");
            MethodInfo? update = PatchUtil.MethodInHierarchy(managerType, "UpdateLogic") ??
                                PatchUtil.MethodInHierarchy(managerType, "Update");

            if (_requestsDict == null || update == null) {
                Logger.Warn("[AntiDDoS] 0012: LiteNetManager.UpdateLogic/_requestsDict not found, skipped");
                return;
            }

            PatchUtil.SafePatch(harmony, update, "0012: bounded connection-request dict (overflow sweep)",
                null, new HarmonyMethod(AccessTools.Method(typeof(PreauthHardening), nameof(RequestsSweepPostfix))));
        }
        catch (Exception e) {
            Logger.Warn($"[AntiDDoS] 0012: patch failed: {e.Message}");
        }
    }

    private static void RequestsSweepPostfix(object __instance) {
        long now = Stopwatch.GetTimestamp();
        if (now < Volatile.Read(ref _nextSweep))
            return;
        if (Interlocked.CompareExchange(ref _nextSweep, now + Stopwatch.Frequency, now) != now)
            return;

        FieldInfo? requestsDict = _requestsDict;
        if (requestsDict == null)
            return;

        try {
            if (requestsDict.GetValue(__instance) is not IDictionary dict)
                return;

            lock (dict) {
                if (dict.Count <= MaxPendingRequests)
                    return;

                dict.Clear();

                long lastLog = Volatile.Read(ref _lastSweepLog);
                if (now - lastLog > 5L * Stopwatch.Frequency &&
                    Interlocked.CompareExchange(ref _lastSweepLog, now, lastLog) == lastLog) {
                    Logger.Warn($"[AntiDDoS] 0012: connection-request backlog exceeded {MaxPendingRequests}, flushed (0012 mitigation)");
                }
            }
        }
        catch {
        }
    }

    private static void PatchUnconnectedRateLimit(Harmony harmony) {
        try {
            Type managerType = typeof(LiteNetLib.LiteNetManager);

            MethodInfo? target = PatchUtil.MethodInHierarchy(managerType, "SendRawAndRecycle");
            if (target == null) {
                foreach (MethodInfo candidate in managerType.GetMethods(
                    BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)) {
                    if (candidate.Name == "SendUnconnectedMessage") {
                        ParameterInfo[] ps = candidate.GetParameters();
                        if (ps.Length == 2 && ps[0].ParameterType == typeof(byte[]) && ps[1].ParameterType == typeof(IPEndPoint)) {
                            target = candidate;
                            break;
                        }
                    }
                }
            }

            if (target == null) {
                Logger.Warn("[AntiDDoS] 0013: SendRawAndRecycle / SendUnconnectedMessage not found, skipped");
                return;
            }

            PatchUtil.SafePatch(harmony, target, "0013: per-IP rate limit on unconnected messages (discovery etc.)",
                new HarmonyMethod(AccessTools.Method(typeof(PreauthHardening), nameof(SendRawPrefix))));
        }
        catch (Exception e) {
            Logger.Warn($"[AntiDDoS] 0013: patch failed: {e.Message}");
        }
    }

    private static bool SendRawPrefix(object __instance, LiteNetLib.NetPacket packet, IPEndPoint remoteEndPoint) {
        if (packet != null && packet.Property == LiteNetLib.PacketProperty.UnconnectedMessage && remoteEndPoint != null) {
            if (IpUtil.IsIpv4(remoteEndPoint.Address) && !_unconnectedLimiter.Allow(IpUtil.IpKey(remoteEndPoint.Address))) {
                Recycle(__instance, packet);
                return false;
            }
        }

        return true;
    }

    private static byte? PropByte(string name) {
        try {
            object value = Enum.Parse(typeof(LiteNetLib.PacketProperty), name);
            return (byte)value;
        }
        catch {
            return null;
        }
    }
}
