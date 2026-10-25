using System.Net;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;

namespace Backend.Services;

public class HfPortalService(ILogger<HfPortalService> logger, IHttpClientFactory httpClientFactory)
{
    private const string PortalBase = "https://softeng-hw.ftsrg.org";

    public async Task<JsonObject> GetStatusAsync(string ltik, CancellationToken ct = default)
    {
        string cleanLtik = ltik.Trim();
        if (string.IsNullOrWhiteSpace(cleanLtik))
        {
            logger.LogError("HF Auth failed: empty ltik");
            throw new ArgumentException();
        }

        HttpClient client = httpClientFactory.CreateClient("HfPortal");
        string escapedLtik = Uri.EscapeDataString(cleanLtik);

        using (HttpResponseMessage authRes = await SendAuthenticatedGetAsync(
            client,
            $"{PortalBase}/api/auth?ltik={escapedLtik}",
            cleanLtik,
            ct))
        {
            if (!authRes.IsSuccessStatusCode)
            {
                string errBody = await authRes.Content.ReadAsStringAsync(ct);
                if (authRes.StatusCode == HttpStatusCode.Forbidden
                    || errBody.Contains("Cloudflare", StringComparison.OrdinalIgnoreCase)
                    || authRes.Headers.Contains("cf-ray"))
                {
                    logger.LogError("HF Portal blocked by Cloudflare. Status: {Status}", authRes.StatusCode);
                    throw new InvalidOperationException();
                }

                logger.LogError("HF Auth failed: {Status} {Err}", authRes.StatusCode, errBody);
                throw new UnauthorizedAccessException();
            }

            JsonObject? authJson = await authRes.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: ct);
            string? instId = authJson?["courseInstanceIds"]?[0]?.ToString();
            if (string.IsNullOrWhiteSpace(instId))
            {
                logger.LogError("HF Auth failed: No course instance found for the user.");
                throw new KeyNotFoundException();
            }

            string escapedInstId = Uri.EscapeDataString(instId);
            HttpResponseMessage instRes = await SendAuthenticatedGetAsync(
                client,
                $"{PortalBase}/api/course-instances/softeng/{escapedInstId}?ltik={escapedLtik}",
                cleanLtik,
                ct);

            try
            {
                if (!instRes.IsSuccessStatusCode)
                {
                    instRes.Dispose();
                    instRes = await SendAuthenticatedGetAsync(
                        client,
                        $"{PortalBase}/api/courses/softeng/{escapedInstId}?ltik={escapedLtik}",
                        cleanLtik,
                        ct);
                }

                if (!instRes.IsSuccessStatusCode)
                {
                    string errBody = await instRes.Content.ReadAsStringAsync(ct);
                    logger.LogError("HF Portal request failed: {Status} {Err}", instRes.StatusCode, errBody);
                    throw new InvalidOperationException();
                }

                JsonObject? instData = await instRes.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: ct);
                if (instData == null)
                {
                    logger.LogError("HF Portal returned null JSON payload with status {Status}", instRes.StatusCode);
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

    private static Task<HttpResponseMessage> SendAuthenticatedGetAsync(
        HttpClient client,
        string url,
        string ltik,
        CancellationToken ct)
    {
        HttpRequestMessage req = new(HttpMethod.Get, url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ltik);
        return client.SendAsync(req, ct);
    }
}
