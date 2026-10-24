using System.Net;
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
            _logger.LogError("HF Auth failed: empty ltik");
            throw new ArgumentException();
        }

        HttpClient client = _httpClientFactory.CreateClient("HfPortal");
        string escapedLtik = Uri.EscapeDataString(cleanLtik);

        string authUrl = $"https://softeng-hw.ftsrg.org/api/auth?ltik={escapedLtik}";
        using HttpRequestMessage authReq = new HttpRequestMessage(HttpMethod.Get, authUrl);
        authReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cleanLtik);

        using HttpResponseMessage authRes = await client.SendAsync(authReq, ct);
        if (!authRes.IsSuccessStatusCode)
        {
            string errBody = await authRes.Content.ReadAsStringAsync(ct);
            if (authRes.StatusCode == HttpStatusCode.Forbidden
                || errBody.Contains("Cloudflare", StringComparison.OrdinalIgnoreCase)
                || authRes.Headers.Contains("cf-ray"))
            {
                _logger.LogError("HF Portal blocked by Cloudflare. Status: {Status}", authRes.StatusCode);
                throw new InvalidOperationException();
            }
            _logger.LogError("HF Auth failed: {Status} {Err}", authRes.StatusCode, errBody);
            throw new UnauthorizedAccessException();
        }

        JsonObject? authJson = await authRes.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: ct);
        string? instId = authJson?["courseInstanceIds"]?[0]?.ToString();
        if (string.IsNullOrWhiteSpace(instId))
        {
            _logger.LogError("HF Auth failed: No course instance found for the user.");
            throw new KeyNotFoundException();
        }

        string escapedInstId = Uri.EscapeDataString(instId);
        string instUrl = $"https://softeng-hw.ftsrg.org/api/course-instances/softeng/{escapedInstId}?ltik={escapedLtik}";
        using HttpRequestMessage instReq = new HttpRequestMessage(HttpMethod.Get, instUrl);
        instReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cleanLtik);

        HttpResponseMessage instRes = await client.SendAsync(instReq, ct);
        try
        {
            if (!instRes.IsSuccessStatusCode)
            {
                instRes.Dispose();
                string altUrl = $"https://softeng-hw.ftsrg.org/api/courses/softeng/{escapedInstId}?ltik={escapedLtik}";
                using HttpRequestMessage altReq = new HttpRequestMessage(HttpMethod.Get, altUrl);
                altReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cleanLtik);
                instRes = await client.SendAsync(altReq, ct);
            }

            if (!instRes.IsSuccessStatusCode)
            {
                string errBody = await instRes.Content.ReadAsStringAsync(ct);
                _logger.LogError("HF Portal request failed: {Status} {Err}", instRes.StatusCode, errBody);
                throw new InvalidOperationException();
            }

            JsonObject? instData = await instRes.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: ct);
            if (instData == null)
            {
                _logger.LogError("HF Portal returned null JSON payload with status {Status}", instRes.StatusCode);
                throw new InvalidOperationException();
            }

            return instData;
        }
        finally
        {
            instRes.Dispose();
        }
    }
}
