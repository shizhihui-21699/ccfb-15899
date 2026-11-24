using System.Security.Cryptography;
using System.Text;

namespace DetentionVerify.Core;

/// <summary>
/// 导入包的签名校验。内网与外网不连通，导包是唯一的数据入口，
/// 因此“这份数据确实来自省级律师管理平台”必须靠密码学校验，而不是靠文件放在哪个目录。
/// 采用 ECDSA P-256 / SHA-256（.NET 内置、国密改造时可平滑替换为 SM2）。
/// </summary>
public static class PackageSignature
{
    public const string AlgorithmEcdsaP256 = "ECDSA-P256-SHA256";

    public static string ComputeSha256Hex(ReadOnlySpan<byte> data) =>
        Convert.ToHexStringLower(SHA256.HashData(data));

    public static string HashFile(string path)
    {
        using var fs = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(fs));
    }

    public static bool Verify(TrustedKey key, ReadOnlySpan<byte> manifestBytes, ReadOnlySpan<byte> signature)
    {
        if (!string.Equals(key.Algorithm, AlgorithmEcdsaP256, StringComparison.OrdinalIgnoreCase))
            return false;

        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(key.PublicKeyBase64), out _);
            return ecdsa.VerifyData(manifestBytes, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static byte[] Sign(ECDsa key, ReadOnlySpan<byte> manifestBytes) =>
        key.SignData(manifestBytes, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    /// <summary>轮换密钥时用于给运维生成 PEM 公钥。</summary>
    public static string ExportPublicKeyPem(ECDsa key) => key.ExportSubjectPublicKeyInfoPem();
}

/// <summary>对结构化对象做稳定序列化，保证哈希可复算。</summary>
public static class CanonicalJson
{
    public static string Of(object value) =>
        System.Text.Json.JsonSerializer.Serialize(value, JsonDefaults.Options);
}

public static class JsonDefaults
{
    public static readonly System.Text.Json.JsonSerializerOptions Options = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static readonly System.Text.Json.JsonSerializerOptions Indented = new(Options)
    {
        WriteIndented = true,
    };
}

/// <summary>仅保存身份证号的加盐哈希与后 6 位，避免内网库成为新的泄露面。</summary>
public static class IdHashing
{
    public static string Hash(string idNumber, string salt)
    {
        var normalized = LicenseNumber.Normalize(idNumber);
        var bytes = Encoding.UTF8.GetBytes(salt + "|" + normalized);
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
    }

    public static string Last6(string idNumber) => LicenseNumber.Last6(idNumber);
}
