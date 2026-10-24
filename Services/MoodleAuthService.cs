using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;

using Backend.DTOs;

namespace Backend.Services;

public partial class MoodleAuthService(ILogger<MoodleAuthService> logger)
{
    private const string MoodleBase = "https://edu.vik.bme.hu";
    private const string IdpBase = "https://idp.bme.hu";
    private const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

    private static readonly HashSet<string> AllowedHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "edu.vik.bme.hu",
        "idp.bme.hu",
        "softeng-hw.ftsrg.org"
    };

    [GeneratedRegex(@"name=""csrf_token""\s+value=""([^""]+)""", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex CsrfTokenRegex();

    [GeneratedRegex(@"<form[^>]*action=""([^""]+)""", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex FormActionRegex();

    [GeneratedRegex(@"name=""SAMLResponse""\s+value=""([^""]+)""", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex SamlResponseRegex();

    [GeneratedRegex(@"name=""RelayState""\s+value=""([^""]+)""", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex RelayStateRegex();

    [GeneratedRegex(@"href=""(moodlemobile://[^""]+)""", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex MoodleMobileHrefRegex();

    [GeneratedRegex(@"window\.location\s*=\s*['""]([^'""]+)['""]", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex WindowLocationRegex();

    [GeneratedRegex(@"ltik=([A-Za-z0-9_.\-]+)", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex LtikRegex();

    [GeneratedRegex(@"<iframe[^>]*src=""([^""]+)""", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex IframeSrcRegex();

    [GeneratedRegex(@"<input[^>]+>", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex InputTagRegex();

    [GeneratedRegex(@"name=""([^""]+)""", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex InputNameRegex();

    [GeneratedRegex(@"value=""([^""]*)""", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex InputValueRegex();

    private static bool IsAllowedUrl(string url, out Uri? validUri)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out validUri)
            && validUri.Scheme == Uri.UriSchemeHttps
            && AllowedHosts.Contains(validUri.Host))
        {
            return true;
        }
        validUri = null;
        return false;
    }

    private static string ResolveUrl(string baseUrl, string relativeOrAbsoluteUrl)
    {
        if (relativeOrAbsoluteUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase))
        {
            return relativeOrAbsoluteUrl;
        }
        return new Uri(new Uri(baseUrl), relativeOrAbsoluteUrl).ToString();
    }

    public async Task<LoginResponseDto> LoginAsync(string username, string password, CancellationToken ct = default)
    {
        logger.LogInformation("Starting login process");
        CookieContainer cookieContainer = new CookieContainer();
        using HttpClientHandler handler = new HttpClientHandler
        {
            CookieContainer = cookieContainer,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.All
        };
        using HttpClient client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(15)
        };
        client.DefaultRequestHeaders.Add("User-Agent", UserAgent);

        // 1. Initiate Shibboleth login on Moodle
        logger.LogInformation("Step 1: Fetching Moodle Shibboleth start page");
        (HttpResponseMessage? resp1, string? _) = await GetWithRedirectsAsync(client, $"{MoodleBase}/auth/shibboleth/index.php", ct);
        if (resp1 == null)
        {
            throw new InvalidOperationException();
        }
        string html1;
        using (resp1)
        {
            html1 = await resp1.Content.ReadAsStringAsync(ct);
        }

        string csrf1 = MatchFirst(CsrfTokenRegex(), html1);
        string action1 = WebUtility.HtmlDecode(MatchFirst(FormActionRegex(), html1));
        if (string.IsNullOrEmpty(csrf1) || string.IsNullOrEmpty(action1))
        {
            logger.LogError("Step 1 failed. HTML: {Html}", html1[..Math.Min(html1.Length, 300)]);
            throw new InvalidOperationException();
        }
        action1 = ResolveUrl(IdpBase, action1);
        if (!IsAllowedUrl(action1, out _))
        {
            logger.LogError("Step 1 blocked disallowed redirect target: {Action}", action1);
            throw new InvalidOperationException();
        }

        // 2. Submit initial IdP session check form
        logger.LogInformation("Step 2: Submitting IdP session check to {Action}", action1);
        using FormUrlEncodedContent form1 = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "csrf_token", csrf1 },
            { "shib_idp_ls_exception.shib_idp_session_ss", "" },
            { "shib_idp_ls_success.shib_idp_session_ss", "false" },
            { "shib_idp_ls_value.shib_idp_session_ss", "" },
            { "shib_idp_ls_exception.shib_idp_persistent_ss", "" },
            { "shib_idp_ls_success.shib_idp_persistent_ss", "false" },
            { "shib_idp_ls_value.shib_idp_persistent_ss", "" },
            { "shib_idp_ls_supported", "" },
            { "_eventId_proceed", "" }
        });

        (HttpResponseMessage? resp2, string? _) = await PostWithRedirectsAsync(client, action1, form1, ct);
        if (resp2 == null)
        {
            throw new InvalidOperationException();
        }
        string html2;
        using (resp2)
        {
            html2 = await resp2.Content.ReadAsStringAsync(ct);
        }

        string csrf2 = MatchFirst(CsrfTokenRegex(), html2);
        string action2 = WebUtility.HtmlDecode(MatchFirst(FormActionRegex(), html2));
        if (string.IsNullOrEmpty(csrf2) || string.IsNullOrEmpty(action2))
        {
            logger.LogError("Step 2 failed. HTML: {Html}", html2[..Math.Min(html2.Length, 300)]);
            throw new InvalidOperationException();
        }
        action2 = ResolveUrl(IdpBase, action2);
        if (!IsAllowedUrl(action2, out _))
        {
            logger.LogError("Step 2 blocked disallowed target: {Action}", action2);
            throw new InvalidOperationException();
        }

        // 3. Submit credentials to BME IdP
        logger.LogInformation("Step 3: Submitting credentials to IdP {Action}", action2);
        using FormUrlEncodedContent form2 = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "j_username", username.Trim() },
            { "j_password", password },
            { "csrf_token", csrf2 },
            { "_eventId_proceed", "" }
        });

        (HttpResponseMessage? resp3, string? _) = await PostWithRedirectsAsync(client, action2, form2, ct);
        if (resp3 == null)
        {
            throw new InvalidOperationException();
        }
        string html3;
        using (resp3)
        {
            html3 = await resp3.Content.ReadAsStringAsync(ct);
        }

        if (html3.Contains("output--error", StringComparison.Ordinal)
            || html3.Contains("cannot be identified", StringComparison.OrdinalIgnoreCase)
            || html3.Contains("Nem sikerült az azonosítás", StringComparison.OrdinalIgnoreCase))
        {
            logger.LogWarning("Invalid credentials provided");
            throw new ArgumentException();
        }

        string samlResponse = MatchFirst(SamlResponseRegex(), html3);
        string relayState = MatchFirst(RelayStateRegex(), html3);
        string spAction = WebUtility.HtmlDecode(MatchFirst(FormActionRegex(), html3));
        if (!string.IsNullOrEmpty(spAction))
        {
            spAction = ResolveUrl(MoodleBase, spAction);
        }

        // Handle potential attribute release / consent form if present
        if (string.IsNullOrEmpty(samlResponse) && html3.Contains("_eventId_proceed", StringComparison.Ordinal))
        {
            logger.LogInformation("Step 3b: Detected consent/attribute form, proceeding...");
            string csrf3 = MatchFirst(CsrfTokenRegex(), html3);
            string consentAction = ResolveUrl(IdpBase, WebUtility.HtmlDecode(MatchFirst(FormActionRegex(), html3)));
            if (!IsAllowedUrl(consentAction, out _))
            {
                throw new InvalidOperationException();
            }

            using FormUrlEncodedContent consentForm = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "csrf_token", csrf3 },
                { "_eventId_proceed", "" }
            });
            (HttpResponseMessage? consentResp, string? _) = await PostWithRedirectsAsync(client, consentAction, consentForm, ct);
            if (consentResp == null)
            {
                throw new InvalidOperationException();
            }
            using (consentResp)
            {
                html3 = await consentResp.Content.ReadAsStringAsync(ct);
            }
            samlResponse = MatchFirst(SamlResponseRegex(), html3);
            relayState = MatchFirst(RelayStateRegex(), html3);
            spAction = WebUtility.HtmlDecode(MatchFirst(FormActionRegex(), html3));
            if (!string.IsNullOrEmpty(spAction))
            {
                spAction = ResolveUrl(MoodleBase, spAction);
            }
        }

        if (string.IsNullOrEmpty(samlResponse) || string.IsNullOrEmpty(spAction) || !IsAllowedUrl(spAction, out _))
        {
            logger.LogError("Step 3 SAML extraction failed. Page snippet: {Snippet}", html3[..Math.Min(html3.Length, 500)]);
            throw new InvalidOperationException();
        }

        logger.LogInformation("Step 4: Submitting SAMLResponse to {SpAction}", spAction);
        // 4. Submit SAMLResponse to Moodle Shibboleth consumer
        using FormUrlEncodedContent form3 = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "SAMLResponse", WebUtility.HtmlDecode(samlResponse) },
            { "RelayState", WebUtility.HtmlDecode(relayState ?? "") }
        });

        (HttpResponseMessage? resp4, string? _) = await PostWithRedirectsAsync(client, spAction, form3, ct);
        if (resp4 != null)
        {
            using (resp4)
            {
                logger.LogInformation("Step 4 response status: {Status}", resp4.StatusCode);
            }
        }

        // 5. Request launch token from Moodle
        string passport = Random.Shared.Next(100_000_000, 999_999_999).ToString();
        string launchUrl = $"{MoodleBase}/admin/tool/mobile/launch.php?service=moodle_mobile_app&passport={passport}&urlscheme=moodlemobile";
        logger.LogInformation("Step 5: Requesting launch URL {Url}", launchUrl);

        string? locationHeader;
        using (HttpResponseMessage launchResp = await client.GetAsync(launchUrl, ct))
        {
            locationHeader = GetLocation(launchResp);
            logger.LogInformation("Step 5 launch response: {Status}, Location: {Loc}", launchResp.StatusCode, locationHeader);

            // If not found in headers, follow or read HTML
            if (string.IsNullOrEmpty(locationHeader))
            {
                string launchHtml = await launchResp.Content.ReadAsStringAsync(ct);
                locationHeader = MatchFirst(MoodleMobileHrefRegex(), launchHtml);
                if (string.IsNullOrEmpty(locationHeader))
                {
                    locationHeader = MatchFirst(WindowLocationRegex(), launchHtml);
                }
                logger.LogInformation("Step 5 extracted from HTML: {Loc}", locationHeader);
            }
        }

        if (string.IsNullOrEmpty(locationHeader) || !locationHeader.Contains("token=", StringComparison.Ordinal))
        {
            CookieCollection cookies = cookieContainer.GetCookies(new Uri(MoodleBase));
            logger.LogError("Step 5 failed. Cookies for moodle: {Cookies}", string.Join(", ", cookies.Cast<Cookie>().Select(c => c.Name)));
            throw new InvalidOperationException();
        }

        // 6. Decode token
        string b64 = locationHeader.Split("token=").Last().Split('&')[0];
        b64 = WebUtility.UrlDecode(b64).Replace('-', '+').Replace('_', '/');
        b64 += new string('=', (4 - (b64.Length % 4)) % 4);
        string wsToken = "";
        try
        {
            string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
            string[] tokenParts = decoded.Split(":::");
            if (tokenParts.Length >= 2 && tokenParts[1].Length == 32)
            {
                wsToken = tokenParts[1];
            }
            else if (decoded.Trim().Length == 32)
            {
                wsToken = decoded.Trim();
            }
        }
        catch (FormatException)
        {
            if (b64.Length == 32) wsToken = b64;
        }

        if (string.IsNullOrEmpty(wsToken) || wsToken.Length != 32)
        {
            logger.LogError("Step 6 token decode failed from: {Loc}", locationHeader);
            throw new InvalidOperationException();
        }
        logger.LogInformation("Step 6: Successfully extracted token {TokenPrefix}...", wsToken[..6]);

        // 7. Fetch user info using core_webservice_get_site_info
        SiteInfoDto? siteInfoJson = null;
        try
        {
            using FormUrlEncodedContent siteInfoContent = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "wstoken", wsToken },
                { "wsfunction", "core_webservice_get_site_info" },
                { "moodlewsrestformat", "json" }
            });
            using HttpResponseMessage siteInfoResp = await client.PostAsync($"{MoodleBase}/webservice/rest/server.php", siteInfoContent, ct);
            if (siteInfoResp.IsSuccessStatusCode)
            {
                siteInfoJson = await siteInfoResp.Content.ReadFromJsonAsync<SiteInfoDto>(cancellationToken: ct);
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning("Failed to fetch user site info (non-blocking): {Msg}", ex.Message);
        }

        // 8. Optionally retrieve LTI launch token for softeng-hw portal
        string? ltik = null;
        try
        {
            ltik = await TryExtractLtiTokenAsync(client, ct);
        }
        catch (Exception ex)
        {
            logger.LogWarning("Optional LTI token extraction failed (non-blocking): {Msg}", ex.Message);
        }

        return new LoginResponseDto(
            Token: wsToken,
            UserId: siteInfoJson?.UserId ?? 0,
            FullName: siteInfoJson?.FullName ?? username,
            Username: siteInfoJson?.Username ?? username,
            Ltik: ltik
        );
    }

    private async Task<string?> TryExtractLtiTokenAsync(HttpClient client, CancellationToken parentCt)
    {
        try
        {
            logger.LogInformation("Step 8: Attempting to retrieve LTI token for module 221136");
            // Strict timeout to avoid exceeding host/cloud router limits (e.g. Heroku 30s)
            using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(parentCt);
            cts.CancelAfter(TimeSpan.FromSeconds(4));
            CancellationToken ct = cts.Token;

            string[] startUrls =
            [
                $"{MoodleBase}/mod/lti/launch.php?id=221136",
                $"{MoodleBase}/mod/lti/view.php?id=221136&forceview=1"
            ];

            foreach (string startUrl in startUrls)
            {
                if (ct.IsCancellationRequested) break;

                (HttpResponseMessage? resp, string? capturedLtik) = await GetWithRedirectsAsync(client, startUrl, ct);
                if (!string.IsNullOrEmpty(capturedLtik))
                {
                    resp?.Dispose();
                    logger.LogInformation("LTI: Captured ltik from initial GET redirect");
                    return capturedLtik;
                }
                if (resp == null) continue;

                try
                {
                    string html = await resp.Content.ReadAsStringAsync(ct);
                    string? loc = GetLocation(resp);
                    if (!string.IsNullOrEmpty(loc) && loc.Contains("ltik=", StringComparison.Ordinal))
                    {
                        return ExtractLtikFromUrl(loc);
                    }
                    Match m = LtikRegex().Match(html);
                    if (m.Success)
                    {
                        logger.LogInformation("LTI: Found ltik in start page HTML");
                        return m.Groups[1].Value;
                    }

                    if (IsCloudflareResponse(resp, html))
                    {
                        logger.LogWarning("LTI: Cloudflare block detected on start page {Url}. Aborting LTI launch.", startUrl);
                        return null;
                    }

                    // Check for iframe
                    string iframeSrc = MatchFirst(IframeSrcRegex(), html);
                    if (!string.IsNullOrEmpty(iframeSrc))
                    {
                        iframeSrc = ResolveUrl(MoodleBase, WebUtility.HtmlDecode(iframeSrc));
                        if (IsAllowedUrl(iframeSrc, out _))
                        {
                            logger.LogInformation("LTI: Following iframe to {IframeSrc}", iframeSrc);
                            (HttpResponseMessage? iframeResp, string? iframeCapturedLtik) = await GetWithRedirectsAsync(client, iframeSrc, ct);
                            if (!string.IsNullOrEmpty(iframeCapturedLtik))
                            {
                                iframeResp?.Dispose();
                                return iframeCapturedLtik;
                            }
                            if (iframeResp != null)
                            {
                                resp.Dispose();
                                resp = iframeResp;
                                html = await resp.Content.ReadAsStringAsync(ct);
                                loc = GetLocation(resp);
                                if (!string.IsNullOrEmpty(loc) && loc.Contains("ltik=", StringComparison.Ordinal))
                                {
                                    return ExtractLtikFromUrl(loc);
                                }
                                if (IsCloudflareResponse(resp, html))
                                {
                                    logger.LogWarning("LTI: Cloudflare block detected on iframe {Url}. Aborting LTI launch.", iframeSrc);
                                    return null;
                                }
                            }
                        }
                    }

                    // Follow auto-submitting forms (LTI launch / OIDC)
                    for (int hop = 0; hop < 5; hop++)
                    {
                        if (ct.IsCancellationRequested) break;

                        string formAction = WebUtility.HtmlDecode(MatchFirst(FormActionRegex(), html));
                        if (string.IsNullOrEmpty(formAction)) break;

                        formAction = ResolveUrl(MoodleBase, formAction);
                        if (!IsAllowedUrl(formAction, out _))
                        {
                            logger.LogWarning("LTI: Blocked form submission to untrusted host: {Action}", formAction);
                            return null;
                        }

                        if (IsCloudflareResponse(resp, html))
                        {
                            logger.LogWarning("LTI: Cloudflare challenge/block detected before submitting hop {Hop} to {Action}. Aborting LTI launch.", hop, formAction);
                            return null;
                        }

                        logger.LogInformation("LTI: Submitting form hop {Hop} to {Action}", hop, formAction);
                        Dictionary<string, string> formData = new Dictionary<string, string>();
                        MatchCollection inputMatches = InputTagRegex().Matches(html);
                        foreach (Match inp in inputMatches)
                        {
                            string tag = inp.Value;
                            string name = MatchFirst(InputNameRegex(), tag);
                            string val = WebUtility.HtmlDecode(MatchFirst(InputValueRegex(), tag));
                            if (!string.IsNullOrEmpty(name))
                            {
                                formData[name] = val;
                            }
                        }

                        using FormUrlEncodedContent postContent = new FormUrlEncodedContent(formData);
                        (HttpResponseMessage? postResp, string? postCapturedLtik) = await PostWithRedirectsAsync(client, formAction, postContent, ct);
                        if (!string.IsNullOrEmpty(postCapturedLtik))
                        {
                            postResp?.Dispose();
                            logger.LogInformation("LTI: Successfully captured ltik during POST hop {Hop} redirect!", hop);
                            return postCapturedLtik;
                        }
                        if (postResp == null) break;

                        resp.Dispose();
                        resp = postResp;

                        string? postLoc = GetLocation(resp);
                        if (!string.IsNullOrEmpty(postLoc) && postLoc.Contains("ltik=", StringComparison.Ordinal))
                        {
                            logger.LogInformation("LTI: Successfully captured ltik from post redirect!");
                            return ExtractLtikFromUrl(postLoc);
                        }

                        html = await resp.Content.ReadAsStringAsync(ct);
                        m = LtikRegex().Match(html);
                        if (m.Success)
                        {
                            logger.LogInformation("LTI: Successfully captured ltik from response HTML!");
                            return m.Groups[1].Value;
                        }

                        if (!resp.IsSuccessStatusCode || IsCloudflareResponse(resp, html))
                        {
                            logger.LogWarning("LTI: Non-success or Cloudflare blocked response ({Status}) from {Action}. Stopping form chain.", resp.StatusCode, formAction);
                            return null;
                        }
                    }
                }
                finally
                {
                    resp.Dispose();
                }
            }
        }
        catch (OperationCanceledException)
        {
            logger.LogWarning("Optional LTI token retrieval timed out (Cloudflare delay / slow network). Continuing without ltik.");
        }
        catch (Exception ex)
        {
            logger.LogWarning("Optional LTI token retrieval failed (non-blocking): {Msg}", ex.Message);
        }
        return null;
    }

    private static bool IsCloudflareResponse(HttpResponseMessage resp, string html)
    {
        if (resp.Headers.Contains("cf-ray") || resp.Headers.Server.Any(s => s.Product?.Name?.Contains("cloudflare", StringComparison.OrdinalIgnoreCase) == true))
        {
            if (resp.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.ServiceUnavailable or HttpStatusCode.TooManyRequests)
            {
                return true;
            }
        }

        return html.Contains("cf-chl-", StringComparison.OrdinalIgnoreCase)
            || html.Contains("cf-challenge", StringComparison.OrdinalIgnoreCase)
            || html.Contains("Just a moment...", StringComparison.OrdinalIgnoreCase)
            || html.Contains("Attention Required! | Cloudflare", StringComparison.OrdinalIgnoreCase)
            || html.Contains("Sorry, you have been blocked", StringComparison.OrdinalIgnoreCase);
    }

    private static string ExtractLtikFromUrl(string url)
    {
        string after = url.Split("ltik=").Last();
        return after.Split('&')[0].Split('#')[0];
    }

    private static string? GetLocation(HttpResponseMessage resp)
    {
        if (resp.Headers.NonValidated.TryGetValues("Location", out HeaderStringValues nonVal))
        {
            return nonVal.FirstOrDefault();
        }
        if (resp.Headers.TryGetValues("Location", out IEnumerable<string>? vals))
        {
            return vals.FirstOrDefault();
        }
        return resp.Headers.Location?.ToString();
    }

    private static async Task<(HttpResponseMessage? Response, string? CapturedLtik)> GetWithRedirectsAsync(HttpClient client, string url, CancellationToken ct = default, int maxRedirects = 5)
    {
        HttpResponseMessage? resp = null;
        for (int i = 0; i < maxRedirects; i++)
        {
            if (ct.IsCancellationRequested) break;

            if (url.Contains("ltik=", StringComparison.Ordinal))
            {
                return (resp, ExtractLtikFromUrl(url));
            }
            if (!IsAllowedUrl(url, out _))
            {
                break;
            }

            resp?.Dispose();
            resp = await client.GetAsync(url, ct);
            string? loc = GetLocation(resp);
            if (!string.IsNullOrEmpty(loc) && loc.Contains("ltik=", StringComparison.Ordinal))
            {
                return (resp, ExtractLtikFromUrl(loc));
            }
            if ((int)resp.StatusCode is >= 300 and <= 399 && !string.IsNullOrEmpty(loc))
            {
                url = ResolveUrl(url, loc);
                continue;
            }
            return (resp, null);
        }
        return (resp, null);
    }

    private static async Task<(HttpResponseMessage? Response, string? CapturedLtik)> PostWithRedirectsAsync(HttpClient client, string url, HttpContent content, CancellationToken ct = default, int maxRedirects = 5)
    {
        if (!IsAllowedUrl(url, out _))
        {
            return (null, null);
        }

        HttpResponseMessage resp = await client.PostAsync(url, content, ct);
        for (int i = 0; i < maxRedirects; i++)
        {
            if (ct.IsCancellationRequested) break;

            string? loc = GetLocation(resp);
            if (!string.IsNullOrEmpty(loc) && loc.Contains("ltik=", StringComparison.Ordinal))
            {
                return (resp, ExtractLtikFromUrl(loc));
            }
            if ((int)resp.StatusCode is >= 300 and <= 399 && !string.IsNullOrEmpty(loc))
            {
                url = ResolveUrl(url, loc);
                if (url.Contains("ltik=", StringComparison.Ordinal))
                {
                    return (resp, ExtractLtikFromUrl(url));
                }
                if (!IsAllowedUrl(url, out _))
                {
                    break;
                }
                resp.Dispose();
                resp = await client.GetAsync(url, ct);
                continue;
            }
            break;
        }
        return (resp, null);
    }

    private static string MatchFirst(Regex regex, string input)
    {
        Match m = regex.Match(input);
        return m.Success ? m.Groups[1].Value : string.Empty;
    }

    private sealed class SiteInfoDto
    {
        [System.Text.Json.Serialization.JsonPropertyName("userid")]
        public int UserId { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("fullname")]
        public string? FullName { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("username")]
        public string? Username { get; set; }
    }
}
