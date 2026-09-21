using System.Net;
using System.Net.Sockets;

namespace AntiDDoS.Tokens;

internal static class IpUtil {
    public static bool IsIpv4(IPAddress ip) =>
        ip != null &&
        (ip.AddressFamily == AddressFamily.InterNetwork || ip.IsIPv4MappedToIPv6);

#pragma warning disable CS0618
    public static uint IpKey(IPAddress ip) =>
        ip.AddressFamily == AddressFamily.InterNetwork
            ? (uint)ip.Address
            : (uint)ip.MapToIPv4().Address;
#pragma warning restore CS0618
}
