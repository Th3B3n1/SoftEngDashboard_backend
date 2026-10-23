using System.Net.Http.Headers;
using System.Text.Json.Nodes;

namespace Backend.Services;

public class HfPortalService(ILogger<HfPortalService> logger, IHttpClientFactory httpClientFactory)
{
    private readonly ILogger<HfPortalService> _logger = logger;
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;

    public async Task<JsonObject> GetStatusAsync(string ltik, CancellationToken ct = default)
    {
        var cleanLtik = ltik.Trim();
        if (cleanLtik.Contains("ltik="))
        {
            cleanLtik = cleanLtik.Split("ltik=")[1].Split('&')[0].Split('#')[0];
        }

        var client = _httpClientFactory.CreateClient("HfPortal");

        var authUrl = $"https://softeng-hw.ftsrg.org/api/auth?ltik={Uri.EscapeDataString(cleanLtik)}";
        using var authReq = new HttpRequestMessage(HttpMethod.Get, authUrl);
        authReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cleanLtik);

        var authRes = await client.SendAsync(authReq, ct);
        if (!authRes.IsSuccessStatusCode)
        {
            var errBody = await authRes.Content.ReadAsStringAsync(ct);
            _logger.LogWarning("HF Auth failed: {Status} {Err}", authRes.StatusCode, errBody);
            throw new UnauthorizedAccessException("A HF Portál token érvénytelen vagy lejárt.");
        }

        var authJson = await authRes.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: ct);
        var instId = authJson?["courseInstanceIds"]?[0]?.ToString();
        if (string.IsNullOrEmpty(instId))
        {
            throw new KeyNotFoundException("Nem található kurzuspéldány a hallgatóhoz.");
        }

        var instUrl = $"https://softeng-hw.ftsrg.org/api/course-instances/softeng/{instId}?ltik={Uri.EscapeDataString(cleanLtik)}";
        using var instReq = new HttpRequestMessage(HttpMethod.Get, instUrl);
        instReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cleanLtik);

        var instRes = await client.SendAsync(instReq, ct);
        if (!instRes.IsSuccessStatusCode)
        {
            var altUrl = $"https://softeng-hw.ftsrg.org/api/courses/softeng/{instId}?ltik={Uri.EscapeDataString(cleanLtik)}";
            using var altReq = new HttpRequestMessage(HttpMethod.Get, altUrl);
            altReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cleanLtik);
            instRes = await client.SendAsync(altReq, ct);
        }

        if (!instRes.IsSuccessStatusCode)
        {
            throw new InvalidOperationException("A kurzuspéldány nem érhető el.");
        }

        var instData = await instRes.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: ct)
            ?? throw new InvalidOperationException("Üres válasz érkezett a HF portáltól.");

        return instData;
    }
}

