using System.Globalization;
using System.Text;

namespace DetentionVerify.Core;

/// <summary>
/// 证号/身份证号的规范化与结构校验。
/// 关键取舍：结构校验只作为“提示”而非“结论”。各地编号规则历史上有变体，
/// 用结构判定“伪造”会误伤真律师；唯一权威是签名名册的查得与否。
/// </summary>
public static class LicenseNumber
{
    private static readonly int[] ProvinceCodes =
    [
        11, 12, 13, 14, 15, 21, 22, 23, 31, 32, 33, 34, 35, 36, 37, 41, 42, 43, 44, 45, 46,
        50, 51, 52, 53, 54, 61, 62, 63, 64, 65, 71, 81, 82,
    ];

    /// <summary>全角数字/字母/标点转半角，去掉所有空白与常见分隔符。</summary>
    public static string Normalize(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        var sb = new StringBuilder(raw.Length);
        foreach (var ch in raw.Trim())
        {
            var c = ch;
            // 全角 ASCII 区（Ａ-Ｚ、ａ-ｚ、０-９、－、＿ 等）整体平移回半角。
            if (c is >= '！' and <= '～') c = (char)(c - 0xFEE0);
            if (char.IsWhiteSpace(c) || c is '-' or '‐' or '–' or '—' or '_' or '.' or '·') continue;
            sb.Append(char.ToUpperInvariant(c));
        }
        return sb.ToString();
    }

    public static string NormalizeName(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        var sb = new StringBuilder(raw.Length);
        foreach (var ch in raw.Trim())
        {
            if (char.IsWhiteSpace(ch) || ch == '　') continue;
            sb.Append(ch);
        }
        return sb.ToString();
    }

    /// <summary>执业证号结构检查，返回 null 表示结构正常，否则返回可读原因。</summary>
    public static string? StructuralIssue(string certNo, DateOnly today)
    {
        if (certNo.Length == 0) return "证号为空";
        foreach (var ch in certNo)
        {
            if (!char.IsAsciiDigit(ch)) return $"证号应为纯数字，实际 {certNo.Length} 位且含非数字字符";
        }
        if (certNo.Length != 17) return $"证号应为 17 位，实际 {certNo.Length} 位";

        var first = certNo[0] - '0';
        if (first is < 1 or > 7) return "第 1 位执业类别不在 1–7 范围内";

        var province = int.Parse(certNo.AsSpan(1, 2), CultureInfo.InvariantCulture);
        if (!ProvinceCodes.Contains(province)) return $"第 2–3 位省级区划代码 {province:00} 不存在";

        // 第 4–7 位在多数省份为区县代码，历史上也存在年份写法，只做弱提示。
        var yearSpan = certNo.AsSpan(4, 4);
        if (yearSpan.ContainsOnlyDigits())
        {
            var year = int.Parse(yearSpan, CultureInfo.InvariantCulture);
            if (year is >= 1949 and <= 2100)
            {
                if (year > today.Year) return $"证号内年份 {year} 晚于当前年份";
                if (year < today.Year - 60) return $"证号内年份 {year} 过早，请确认";
            }
        }
        return null;
    }

    /// <summary>省级区划是否合法（用于提示可能的录入错误）。</summary>
    public static bool HasKnownProvince(string certNo) =>
        certNo.Length >= 3 && int.TryParse(certNo.AsSpan(1, 2), out var p) && ProvinceCodes.Contains(p);

    /// <summary>GB 11643-1999 十八位身份证校验。返回 null 表示合法。</summary>
    public static string? IdNumberIssue(string? raw)
    {
        var id = Normalize(raw);
        if (id.Length == 0) return "身份证号为空";
        if (id.Length != 18) return $"身份证号应为 18 位，实际 {id.Length} 位";
        if (!id.AsSpan(0, 17).ContainsOnlyDigits()) return "身份证号前 17 位应为数字";
        if (id[17] != 'X' && !char.IsAsciiDigit(id[17])) return "身份证号校验位非法";

        if (!int.TryParse(id.AsSpan(0, 2), out var province) || !ProvinceCodes.Contains(province))
            return "身份证号省级区划代码不存在";

        var birth = id.Substring(6, 8);
        if (!DateTime.TryParseExact(birth, "yyyyMMdd", CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var dob))
            return "身份证号内出生日期不成立";
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        if (dob.Year < 1900 || DateOnly.FromDateTime(dob) > today)
            return "身份证号内出生日期超出合理范围";

        int[] weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
        const string checkChars = "10X98765432";
        var sum = 0;
        for (var i = 0; i < 17; i++) sum += (id[i] - '0') * weights[i];
        var expected = checkChars[sum % 11];
        return id[17] == expected ? null : $"身份证号校验位不符（末位应为 {expected}）";
    }

    public static DateOnly? BirthDateFromId(string? raw)
    {
        var id = Normalize(raw);
        if (id.Length != 18) return null;
        return DateOnly.TryParseExact(id.AsSpan(6, 8), "yyyyMMdd", CultureInfo.InvariantCulture,
            DateTimeStyles.None, out var d) ? d : null;
    }

    public static string Last6(string? raw)
    {
        var id = Normalize(raw);
        return id.Length >= 6 ? id[^6..] : string.Empty;
    }

    /// <summary>编辑距离，用于“是不是输错了一位”的近似提示。</summary>
    public static int Distance(string a, string b, int cap = 4)
    {
        if (a == b) return 0;
        if (Math.Abs(a.Length - b.Length) > cap) return cap + 1;
        var prev = new int[b.Length + 1];
        var cur = new int[b.Length + 1];
        for (var j = 0; j <= b.Length; j++) prev[j] = j;
        for (var i = 1; i <= a.Length; i++)
        {
            cur[0] = i;
            var rowBest = cur[0];
            for (var j = 1; j <= b.Length; j++)
            {
                var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                cur[j] = Math.Min(Math.Min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
                if (cur[j] < rowBest) rowBest = cur[j];
            }
            if (rowBest > cap) return cap + 1;
            (prev, cur) = (cur, prev);
        }
        return prev[b.Length];
    }
}

internal static class SpanExtensions
{
    public static bool ContainsOnlyDigits(this ReadOnlySpan<char> span)
    {
        foreach (var c in span) if (!char.IsAsciiDigit(c)) return false;
        return true;
    }
}
