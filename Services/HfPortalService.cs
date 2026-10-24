using System.Net.Http.Headers;
using System.Text.Json.Nodes;

namespace Backend.Services;

public class HfPortalService(ILogger<HfPortalService> logger, IHttpClientFactory httpClientFactory)
{
    private readonly ILogger<HfPortalService> _logger = logger;
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;

    public async Task<JsonObject> GetStatusAsync(string ltik, CancellationToken ct = default)
    {
        string cleanLtik = ltik.Trim();
        if (string.IsNullOrWhiteSpace(cleanLtik))
        {
            throw new ArgumentException("Érvénytelen vagy hiányzó ltik token.");
        }

        HttpClient client = _httpClientFactory.CreateClient("HfPortal");

        string authUrl = $"https://softeng-hw.ftsrg.org/api/auth?ltik={Uri.EscapeDataString(cleanLtik)}";
        using HttpRequestMessage authReq = new HttpRequestMessage(HttpMethod.Get, authUrl);
        authReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cleanLtik);

        HttpResponseMessage authRes = await client.SendAsync(authReq, ct);
        if (!authRes.IsSuccessStatusCode)
        {
            string errBody = await authRes.Content.ReadAsStringAsync(ct);
            _logger.LogWarning("HF Auth failed: {Status} {Err}", authRes.StatusCode, errBody);
            throw new UnauthorizedAccessException("A HF Portál token érvénytelen vagy lejárt.");
        }

        JsonObject? authJson = await authRes.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: ct);
        string? instId = authJson?["courseInstanceIds"]?[0]?.ToString();
        if (string.IsNullOrEmpty(instId))
        {
            throw new KeyNotFoundException("Nem található kurzuspéldány a hallgatóhoz.");
        }

        string instUrl = $"https://softeng-hw.ftsrg.org/api/course-instances/softeng/{instId}?ltik={Uri.EscapeDataString(cleanLtik)}";
        using HttpRequestMessage instReq = new HttpRequestMessage(HttpMethod.Get, instUrl);
        instReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cleanLtik);

        HttpResponseMessage instRes = await client.SendAsync(instReq, ct);
        if (!instRes.IsSuccessStatusCode)
        {
            string altUrl = $"https://softeng-hw.ftsrg.org/api/courses/softeng/{instId}?ltik={Uri.EscapeDataString(cleanLtik)}";
            using HttpRequestMessage altReq = new HttpRequestMessage(HttpMethod.Get, altUrl);
            altReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cleanLtik);
            instRes = await client.SendAsync(altReq, ct);
        }

        if (!instRes.IsSuccessStatusCode)
        {
            throw new InvalidOperationException("A kurzuspéldány nem érhető el.");
        }

        JsonObject instData = await instRes.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: ct)
            ?? throw new InvalidOperationException("Üres válasz érkezett a HF portáltól.");

        return instData;
    }
}

