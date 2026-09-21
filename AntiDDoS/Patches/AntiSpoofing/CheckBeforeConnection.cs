using AntiDDoS.Tokens;
using HarmonyLib;
using LiteNetLib;
using Steam;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace AntiDDoS.Patches.AntiSpoofing;

[HarmonyPatch(typeof(LiteNetManager), nameof(LiteNetManager.OnMessageReceived))]
internal static class CheckBeforeConnection {
    private const long TrustTtlSeconds = 86400;

    private const int ConnectionTimeOffset = 5;
    private const int ConnectionTimeLength = 8;
    private const int ConnectDataLengthOffset = 38;
    private const int MinConnectRequestSize = ConnectDataLengthOffset + 1;

    private const int SeqPrefixLength = 4;
    private const int SeqResponseTokenLength = sizeof(uint);
    private const int SeqChallengeSize = SeqPrefixLength + 1 + SeqResponseTokenLength;

    private const byte SeqInfo = 0x54;
    private const byte SeqChallenge = 0x41;

    private const byte ChallengePayloadSize = 13;

    private const int DisconnectHeaderSize = 1 + ConnectionTimeLength + 1;
    private const int ChallengeReplySize =
        DisconnectHeaderSize + 1 + sizeof(int) + sizeof(ushort) + ChallengeResponse.TokenSize;

    [ThreadStatic]
    private static byte[]? _challengeReplyBuffer;
    [ThreadStatic]
    private static byte[]? _seqChallengeBuffer;

    private static readonly IpTrustList _whiteList = new(TrustTtlSeconds);
    private static readonly IpRateLimiter _challengeLimiter = new(200);
    private static readonly IpRateLimiter _seqChallengeLimiter = new(200);
    private static readonly IpRateLimiter _seqReplyLimiter = new(1000);

    public static long WhitelistCount => _whiteList.Count;
    public static long ChallengeSentTotal;
    public static long ValidatedTotal;
    public static long SeqTotal;

    private static bool Prefix(LiteNetManager __instance, NetPacket packet, IPEndPoint? remoteEndPoint) {
        if (remoteEndPoint != null && __instance.TryGetPeer(remoteEndPoint, out _)) {
            if (IpUtil.IsIpv4(remoteEndPoint.Address))
                _whiteList.Trust(IpUtil.IpKey(remoteEndPoint.Address), FastClock.UnixSeconds());
            return true;
        }

        ReadOnlySpan<byte> data = packet.RawData.AsSpan(0, packet.Size);

#pragma warning disable CS8602 // Dereference of a possibly null reference.

        IPAddress rawAddr = remoteEndPoint.Address;
#pragma warning restore CS8602 // Dereference of a possibly null reference.


        if (data.IsEmpty) {
            if (IpUtil.IsIpv4(rawAddr) && _whiteList.IsTrusted(IpUtil.IpKey(rawAddr), FastClock.UnixSeconds()))
                return true;

            __instance.PoolRecycle(packet);
            return false;
        }

        if (rawAddr.AddressFamily != AddressFamily.InterNetwork && !rawAddr.IsIPv4MappedToIPv6)
            return true;

        if (IsSourceEngineQuery(data)) {
            PreAuthLogger.Processed++;
            Interlocked.Increment(ref PreAuthLogger.ProcessedTotal);

            ProcessSEQ(__instance, data, remoteEndPoint);
            __instance.PoolRecycle(packet);
            return false;
        }

        uint ipKey = IpUtil.IpKey(rawAddr);

        if (_whiteList.IsTrusted(ipKey, FastClock.UnixSeconds())) {
            _whiteList.Trust(ipKey, FastClock.UnixSeconds());
            return true;
        }

        if (packet.Property != PacketProperty.ConnectRequest) {
            __instance.PoolRecycle(packet);
            return false;
        }

        PreAuthLogger.Processed++;
        Interlocked.Increment(ref PreAuthLogger.ProcessedTotal);

        if (!TryParseChallenge(data, out int nonce, out ReadOnlySpan<byte> challenge)) {
            __instance.PoolRecycle(packet);
            return false;
        }

        ReadOnlySpan<byte> connTime = data.Slice(ConnectionTimeOffset, ConnectionTimeLength);

        if (nonce == 0 || challenge.IsEmpty) {
            if (_challengeLimiter.Allow(ipKey)) {
                Interlocked.Increment(ref ChallengeSentTotal);
                SendChallengeRequest(__instance, remoteEndPoint, connTime, ipKey);
            }
        }
        else {
            if (!ChallengeResponse.Instance.Validate(ipKey, challenge)) {
                __instance.PoolRecycle(packet);
                return false;
            }

            _whiteList.Trust(ipKey, FastClock.UnixSeconds());
            Interlocked.Increment(ref ValidatedTotal);
            return true;
        }

        __instance.PoolRecycle(packet);
        return false;
    }

    public static void Prune() {
        long now = FastClock.UnixSeconds();

        _whiteList.Prune(now);
        _challengeLimiter.Prune();
        _seqChallengeLimiter.Prune();
        _seqReplyLimiter.Prune();

        PruneVanillaChallenges();
    }

    private static void PruneVanillaChallenges() {
        try {
            long cutoff = DateTime.Now.Ticks - TimeSpan.FromSeconds(15).Ticks;
            foreach (KeyValuePair<string, PreauthChallengeItem> kvp in CustomLiteNetLib4MirrorTransport.Challenges) {
                if (kvp.Value.Added < cutoff)
                    CustomLiteNetLib4MirrorTransport.Challenges.TryRemove(kvp.Key, out _);
            }
        }
        catch {
        }
    }

    private static bool IsSourceEngineQuery(ReadOnlySpan<byte> data) =>
        data.Length >= SeqChallengeSize &&
        BinaryPrimitives.ReadUInt32LittleEndian(data) == 0xFFFFFFFF;

    private static void ProcessSEQ(LiteNetManager instance, ReadOnlySpan<byte> data, IPEndPoint ep) {
        if (data[SeqPrefixLength] != SeqInfo)
            return;

        ReadOnlySpan<byte> payload = data[(SeqPrefixLength + 1)..];
        int nullIdx = payload.IndexOf((byte)0);
        if (nullIdx < 0)
            return;

        ReadOnlySpan<byte> afterNull = payload[(nullIdx + 1)..];

        uint seqIpKey = IpUtil.IpKey(ep.Address);
        Interlocked.Increment(ref SeqTotal);

        if (afterNull.Length >= SeqResponseTokenLength) {
            uint response = BinaryPrimitives.ReadUInt32LittleEndian(afterNull);

            if (SourceEngineQuery.Instance.Validate(seqIpKey, response)) {
                if (_seqReplyLimiter.Allow(seqIpKey))
                    instance._udpSocketv4.SendTo(SteamServerInfo.Serialize(), SocketFlags.None, ep);
            }
            else
                NetDebug.WriteError($"[SEQ] Bad HMAC from {ep}");

            return;
        }

        if (!_seqChallengeLimiter.Allow(seqIpKey))
            return;

        byte[] buf = _seqChallengeBuffer ??= new byte[SeqChallengeSize];
        Span<byte> span = buf.AsSpan(0, SeqChallengeSize);

        BinaryPrimitives.WriteUInt32LittleEndian(span, 0xFFFFFFFF);
        span[4] = SeqChallenge;
        BinaryPrimitives.WriteUInt32LittleEndian(span[5..], SourceEngineQuery.Instance.Generate(seqIpKey));

        instance._udpSocketv4.SendTo(buf, 0, SeqChallengeSize, SocketFlags.None, ep);
    }

    private static bool TryParseChallenge(
        ReadOnlySpan<byte> data,
        out int nonce,
        out ReadOnlySpan<byte> challenge) {
        nonce = 0;
        challenge = default;

        if (data.Length < MinConnectRequestSize)
            return false;

        byte customLen = data[ConnectDataLengthOffset];
        int cursor = ConnectDataLengthOffset + 1 + customLen;

        if (data.Length < cursor + sizeof(int))
            return true;

        nonce = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(cursor, sizeof(int)));
        cursor += sizeof(int);

        if (data.Length < cursor + sizeof(ushort))
            return true;

        int challengeLen = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(cursor, sizeof(ushort)));
        cursor += sizeof(ushort);

        if (data.Length < cursor + challengeLen)
            return false;

        challenge = data.Slice(cursor, challengeLen);
        return true;
    }

    private static void SendChallengeRequest(LiteNetManager instance, IPEndPoint ep, ReadOnlySpan<byte> connTime, uint ipKey) {
        if (CustomLiteNetLib4MirrorTransport.Challenges.Count > 5000) {
            PruneVanillaChallenges();
            if (CustomLiteNetLib4MirrorTransport.Challenges.Count > 10000)
                CustomLiteNetLib4MirrorTransport.Challenges.Clear();
        }

        int nonce = global::RandomGenerator.GetInt32();
        if (nonce == 0)
            nonce = 1;

        byte[] token = new byte[ChallengeResponse.TokenSize];
        ChallengeResponse.Instance.GenerateTo(ipKey, token);

        string challengeKey = ep.Address.ToString() + "-" + nonce;
        CustomLiteNetLib4MirrorTransport.Challenges[challengeKey] =
            new PreauthChallengeItem(new ArraySegment<byte>(token));

        byte[] buf = _challengeReplyBuffer ??= new byte[ChallengeReplySize];
        Span<byte> span = buf.AsSpan(0, ChallengeReplySize);
        int cur = 0;

        span[cur++] = (byte)PacketProperty.Disconnect;
        connTime.CopyTo(span.Slice(cur, ConnectionTimeLength));
        cur += ConnectionTimeLength;

        span[cur++] = ChallengePayloadSize;
        span[cur++] = (byte)ChallengeType.Reply;
        BinaryPrimitives.WriteInt32LittleEndian(span.Slice(cur, sizeof(int)), nonce);
        cur += sizeof(int);

        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(cur, sizeof(ushort)), (ushort)token.Length);
        cur += sizeof(ushort);

        token.CopyTo(span.Slice(cur, token.Length));

        instance._udpSocketv4.SendTo(buf, 0, ChallengeReplySize, SocketFlags.None, ep);
    }
}
