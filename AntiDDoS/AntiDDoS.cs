using AntiDDoS.Patches.Compat;
using HarmonyLib;
using LabApi.Features;
using LabApi.Loader.Features.Plugins;

namespace AntiDDoS;

internal class AntiDDoS : Plugin {
    private Harmony? _harmony;

    public override string Name { get; } = nameof(AntiDDoS);
    public override string Description { get; } = "Anti-DDoS plugin: connection attack protection, netcode hardening, optimizations and exploit fixes.";
    public override string Author { get; } = "Vymi Platforms LLC, developed by wexels.dev, based on ФУТУР's plugin";
    public override Version Version { get; } = new Version(2, 0);
    public override Version RequiredApiVersion { get; } = new Version(LabApiProperties.CompiledVersion);

    public override void Enable() {
        Patches.SecureNetThreading.InitializeMainThread();
        this._harmony = new Harmony($"{this.Author}.{this.Name}-{DateTime.Now}");
        this._harmony.PatchAll();

        PatchUtil.SafeModule("0011 fragment TTL", () => Patches.Exploits.FragmentTtl.Apply(this._harmony));
        PatchUtil.SafeModule("0014 unbatcher cap", () => Patches.Exploits.UnbatcherGuard.Apply(this._harmony));
        PatchUtil.SafeModule("0014 transport max size", () => Patches.Transport.TransportLimits.Apply(this._harmony));
        PatchUtil.SafeModule("0015 events budget", () => Patches.Transport.EventsBudget.Apply(this._harmony));
        PatchUtil.SafeModule("message rate guard", () => Patches.Exploits.MessageRateGuard.Apply(this._harmony));
        PatchUtil.SafeModule("0004/0012/0013/0022 preauth hardening", () => Patches.Preauth.PreauthHardening.Apply(this._harmony));
        PatchUtil.SafeModule("0019 subroutine guard", () => Patches.Gameplay.SubroutineGuard.Apply(this._harmony));
        PatchUtil.SafeModule("0021 voice guard", () => Patches.Gameplay.VoiceGuard.Apply(this._harmony));
        PatchUtil.SafeModule("AFK & inactivity guard", () => Patches.Gameplay.AfkGuard.Apply(this._harmony));
    }

    public override void Disable() {
        this._harmony?.UnpatchAll(this._harmony.Id);
        this._harmony = null;
    }
}
