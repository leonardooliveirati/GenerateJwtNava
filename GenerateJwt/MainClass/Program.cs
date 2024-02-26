using System;
using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

public class MainClass
{
    public static string GenerateJwtWithFixedClaims(string secret, string issuer, string audience, string sub, string jti, long iat)
    {
        var header = new { alg = "HS256", typ = "JWT" };
        var payload = new { sub, jti, iat, iss = issuer, aud = audience };

        var headerBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header));
        var payloadBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload));

        var encodedHeader = Base64UrlEncode(headerBytes);
        var encodedPayload = Base64UrlEncode(payloadBytes);

        var signatureInput = $"{encodedHeader}.{encodedPayload}";
        var secretBytes = Encoding.UTF8.GetBytes(secret);
        var hmac = new HMACSHA256(secretBytes);
        var signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(signatureInput));
        var encodedSignature = Base64UrlEncode(signatureBytes);

        return $"{encodedHeader}.{encodedPayload}.{encodedSignature}";
    }

    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .Replace('+', '-')
            .Replace('/', '_')
            .Replace("=", "");
    }

    public static void Main(string[] args)
    {
        string jwt = GenerateJwtWithFixedClaims("your-secret-key-1234", "your-issuer", "your-audience", "sub-value-1", "jti-value-1", 1626300000);
        Console.WriteLine(jwt);
    }
}
