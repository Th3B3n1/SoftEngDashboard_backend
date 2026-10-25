using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Backend.Services;

public static partial class MoodleTokenCrypto
{
    private const string Prefix = "enc:";
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private static readonly byte[] Key = DeriveKey();

    [GeneratedRegex(@"^[0-9a-fA-F]{32}$", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 500)]
    private static partial Regex RawHexTokenRegex();

    private static byte[] DeriveKey()
    {
        string secret = Environment.GetEnvironmentVariable("TOKEN_ENCRYPTION_KEY")
            ?? "SoftDevBMEDash-VIK-Course550-TokenKey-2026";
        return SHA256.HashData(Encoding.UTF8.GetBytes(secret));
    }

    public static bool IsValidRawToken(string token) =>
        !string.IsNullOrWhiteSpace(token) && RawHexTokenRegex().IsMatch(token.Trim());

    public static string Protect(string rawWsToken)
    {
        string clean = rawWsToken.Trim();
        if (!IsValidRawToken(clean))
        {
            throw new ArgumentException("Invalid raw Moodle token format.");
        }

        byte[] plaintext = Encoding.UTF8.GetBytes(clean);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];

        using (AesGcm aes = new AesGcm(Key, TagSize))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
        }

        byte[] combined = new byte[NonceSize + TagSize + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, combined, 0, NonceSize);
        Buffer.BlockCopy(tag, 0, combined, NonceSize, TagSize);
        Buffer.BlockCopy(ciphertext, 0, combined, NonceSize + TagSize, ciphertext.Length);

        string base64Url = Convert.ToBase64String(combined)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

        return Prefix + base64Url;
    }

    public static string? Unprotect(string? tokenInput)
    {
        if (string.IsNullOrWhiteSpace(tokenInput))
        {
            return null;
        }

        string trimmed = tokenInput.Trim();

        // Allow raw 32-char hex token if passed directly (e.g. during initial exchange)
        if (IsValidRawToken(trimmed))
        {
            return trimmed;
        }

        if (!trimmed.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return null;
        }

        string b64 = trimmed[Prefix.Length..]
            .Replace('-', '+')
            .Replace('_', '/');
        b64 += new string('=', (4 - (b64.Length % 4)) % 4);

        try
        {
            byte[] combined = Convert.FromBase64String(b64);
            if (combined.Length <= NonceSize + TagSize)
            {
                return null;
            }

            byte[] nonce = combined[..NonceSize];
            byte[] tag = combined[NonceSize..(NonceSize + TagSize)];
            byte[] ciphertext = combined[(NonceSize + TagSize)..];
            byte[] plaintext = new byte[ciphertext.Length];

            using (AesGcm aes = new AesGcm(Key, TagSize))
            {
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
            }

            string rawToken = Encoding.UTF8.GetString(plaintext);
            return IsValidRawToken(rawToken) ? rawToken : null;
        }
        catch (CryptographicException)
        {
            return null;
        }
        catch (FormatException)
        {
            return null;
        }
    }
}

