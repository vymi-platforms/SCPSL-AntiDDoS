using System.Reflection;
using LabApi.Features.Console;
using HarmonyLib;

namespace AntiDDoS.Patches.Compat;

internal static class PatchUtil {
    public static bool SafePatch(Harmony harmony, MethodBase? target, string label,
        HarmonyMethod? prefix = null, HarmonyMethod? postfix = null) {
        if (target == null) {
            Logger.Warn($"[AntiDDoS] {label}: target not found, skipped");
            return false;
        }

        try {
            harmony.Patch(target, prefix, postfix);
            Logger.Info($"[AntiDDoS] {label}: applied");
            return true;
        }
        catch (Exception e) {
            Logger.Warn($"[AntiDDoS] {label}: patch failed: {e.Message}");
            return false;
        }
    }

    public static void SafeModule(string label, Action action) {
        try {
            action();
        }
        catch (Exception e) {
            Logger.Warn($"[AntiDDoS] module {label}: init failed: {e}");
        }
    }
    public static Type? FindType(string? name) {
        if (string.IsNullOrEmpty(name))
            return null;

        Type? direct = Type.GetType(name, false);
        if (direct != null)
            return direct;

        foreach (Assembly assembly in AppDomain.CurrentDomain.GetAssemblies()) {
            Type[] types;
            try {
                types = assembly.GetTypes();
            }
            catch {
                continue;
            }

            foreach (Type type in types) {
                if (type.FullName == name || type.Name == name)
                    return type;
            }
        }

        return null;
    }

    public static FieldInfo? FieldInHierarchy(Type? type, string name) {
        for (Type? t = type; t != null && t != typeof(object); t = t.BaseType) {
            FieldInfo? field = t.GetField(name,
                BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
            if (field != null)
                return field;
        }

        return null;
    }

    public static PropertyInfo? PropertyInHierarchy(Type? type, string name) {
        for (Type? t = type; t != null && t != typeof(object); t = t.BaseType) {
            PropertyInfo? property = t.GetProperty(name,
                BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
            if (property != null)
                return property;
        }

        return null;
    }

    public static MethodInfo? MethodInHierarchy(Type? type, string name) {
        for (Type? t = type; t != null && t != typeof(object); t = t.BaseType) {
            MethodInfo[] methods = t.GetMethods(
                BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
            foreach (MethodInfo method in methods) {
                if (method.Name == name)
                    return method;
            }
        }

        return null;
    }
}
