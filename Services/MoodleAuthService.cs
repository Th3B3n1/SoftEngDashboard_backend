using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;

using Backend.DTOs;

namespace Backend.Services;

public class MoodleAuthService(ILogger<MoodleAuthService> logger)
{
    private const string MoodleBase = "https://edu.vik.bme.hu";
    private const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

    public async Task<LoginResponseDto> LoginAsync(string username, string password)
    {
        logger.LogInformation("Starting login process");
        CookieContainer cookieContainer = new CookieContainer();
        using HttpClientHandler handler = new HttpClientHandler
        {
            CookieContainer = cookieContainer,
            AllowAutoRedirect = false,
        };
        using HttpClient client = new HttpClient(handler);
        client.DefaultRequestHeaders.Add("User-Agent", UserAgent);

        // 1. Initiate Shibboleth login on Moodle
        logger.LogInformation("Step 1: Fetching Moodle Shibboleth start page");
        (HttpResponseMessage? resp1, string? _) = await GetWithRedirectsAsync(client, $"{MoodleBase}/auth/shibboleth/index.php");
        string html1 = await resp1.Content.ReadAsStringAsync();

        string csrf1 = MatchGroup(html1, @"name=""csrf_token""\s+value=""([^""]+)""");
        string action1 = MatchGroup(html1, @"<form[^>]*action=""([^""]+)""");
        if (string.IsNullOrEmpty(csrf1) || string.IsNullOrEmpty(action1))
        {
            logger.LogError("Step 1 failed. HTML: {Html}", html1[..Math.Min(html1.Length, 300)]);
            throw new InvalidOperationException("Nem sikerült elindítani a Shibboleth azonosítást.");
        }
        if (!action1.StartsWith("http")) action1 = "https://idp.bme.hu" + action1;

        // 2. Submit initial IdP session check form
        logger.LogInformation("Step 2: Submitting IdP session check to {Action}", action1);
        FormUrlEncodedContent form1 = new FormUrlEncodedContent(new Dictionary<string, string>
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

        (HttpResponseMessage? resp2, string? _) = await PostWithRedirectsAsync(client, action1, form1);
        string html2 = await resp2.Content.ReadAsStringAsync();

        string csrf2 = MatchGroup(html2, @"name=""csrf_token""\s+value=""([^""]+)""");
        string action2 = MatchGroup(html2, @"<form[^>]*action=""([^""]+)""");
        if (string.IsNullOrEmpty(csrf2) || string.IsNullOrEmpty(action2))
        {
            logger.LogError("Step 2 failed. HTML: {Html}", html2[..Math.Min(html2.Length, 300)]);
            throw new InvalidOperationException("A BME IdP bejelentkező űrlap nem tölthető be.");
        }
        if (!action2.StartsWith("http")) action2 = "https://idp.bme.hu" + action2;

        // 3. Submit credentials to BME IdP
        logger.LogInformation("Step 3: Submitting credentials to IdP {Action}", action2);
        FormUrlEncodedContent form2 = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "j_username", username.Trim() },
            { "j_password", password },
            { "csrf_token", csrf2 },
            { "_eventId_proceed", "" }
        });

        (HttpResponseMessage? resp3, string? _) = await PostWithRedirectsAsync(client, action2, form2);
        string html3 = await resp3.Content.ReadAsStringAsync();

        if (html3.Contains("output--error") || html3.Contains("cannot be identified") || html3.Contains("Nem sikerült az azonosítás"))
        {
            logger.LogWarning("Invalid credentials provided");
            throw new ArgumentException("Érvénytelen felhasználónév vagy jelszó.");
        }

        string samlResponse = MatchGroup(html3, @"name=""SAMLResponse""\s+value=""([^""]+)""");
        string relayState = MatchGroup(html3, @"name=""RelayState""\s+value=""([^""]+)""");
        string spAction = WebUtility.HtmlDecode(MatchGroup(html3, @"<form[^>]*action=""([^""]+)"""));
        if (!string.IsNullOrEmpty(spAction) && !spAction.StartsWith("http"))
        {
            spAction = $"{MoodleBase}" + (spAction.StartsWith('/') ? "" : "/") + spAction;
        }

        // Handle potential attribute release / consent form if present
        if (string.IsNullOrEmpty(samlResponse) && html3.Contains("_eventId_proceed"))
        {
            logger.LogInformation("Step 3b: Detected consent/attribute form, proceeding...");
            string csrf3 = MatchGroup(html3, @"name=""csrf_token""\s+value=""([^""]+)""");
            string consentAction = WebUtility.HtmlDecode(MatchGroup(html3, @"<form[^>]*action=""([^""]+)"""));
            if (!consentAction.StartsWith("http")) consentAction = "https://idp.bme.hu" + consentAction;

            FormUrlEncodedContent consentForm = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "csrf_token", csrf3 },
                { "_eventId_proceed", "" }
            });
            (HttpResponseMessage? consentResp, string? _) = await PostWithRedirectsAsync(client, consentAction, consentForm);
            html3 = await consentResp.Content.ReadAsStringAsync();
            samlResponse = MatchGroup(html3, @"name=""SAMLResponse""\s+value=""([^""]+)""");
            relayState = MatchGroup(html3, @"name=""RelayState""\s+value=""([^""]+)""");
            spAction = WebUtility.HtmlDecode(MatchGroup(html3, @"<form[^>]*action=""([^""]+)"""));
            if (!string.IsNullOrEmpty(spAction) && !spAction.StartsWith("http"))
            {
                spAction = $"{MoodleBase}" + (spAction.StartsWith('/') ? "" : "/") + spAction;
            }
        }

        if (string.IsNullOrEmpty(samlResponse) || string.IsNullOrEmpty(spAction))
        {
            logger.LogError("Step 3 SAML extraction failed. Page snippet: {Snippet}", html3[..Math.Min(html3.Length, 500)]);
            throw new InvalidOperationException("A BME IdP nem adott vissza érvényes SAML választ.");
        }

        logger.LogInformation("Step 4: Submitting SAMLResponse to {SpAction}", spAction);
        // 4. Submit SAMLResponse to Moodle Shibboleth consumer
        FormUrlEncodedContent form3 = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "SAMLResponse", WebUtility.HtmlDecode(samlResponse) },
            { "RelayState", WebUtility.HtmlDecode(relayState ?? "") }
        });

        (HttpResponseMessage? resp4, string? _) = await PostWithRedirectsAsync(client, spAction, form3);
        logger.LogInformation("Step 4 response status: {Status}", resp4.StatusCode);

        // 5. Request launch token from Moodle
        string passport = Random.Shared.Next(100_000_000, 999_999_999).ToString();
        string launchUrl = $"{MoodleBase}/admin/tool/mobile/launch.php?service=moodle_mobile_app&passport={passport}&urlscheme=moodlemobile";
        logger.LogInformation("Step 5: Requesting launch URL {Url}", launchUrl);

        HttpResponseMessage launchResp = await client.GetAsync(launchUrl);
        string? locationHeader = GetLocation(launchResp);

        logger.LogInformation("Step 5 launch response: {Status}, Location: {Loc}", launchResp.StatusCode, locationHeader);

        // If not found in headers, follow or read HTML
        if (string.IsNullOrEmpty(locationHeader))
        {
            string launchHtml = await launchResp.Content.ReadAsStringAsync();
            locationHeader = MatchGroup(launchHtml, @"href=""(moodlemobile://[^""]+)""");
            if (string.IsNullOrEmpty(locationHeader))
            {
                locationHeader = MatchGroup(launchHtml, @"window\.location\s*=\s*['""]([^'""]+)['""]");
            }
            logger.LogInformation("Step 5 extracted from HTML: {Loc}", locationHeader);
        }

        if (string.IsNullOrEmpty(locationHeader) || !locationHeader.Contains("token="))
        {
            CookieCollection cookies = cookieContainer.GetCookies(new Uri(MoodleBase));
            logger.LogError("Step 5 failed. Cookies for moodle: {Cookies}", string.Join(", ", cookies.Cast<Cookie>().Select(c => c.Name)));
            throw new InvalidOperationException("A Moodle nem generált mobil hozzáférési tokent.");
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
            throw new InvalidOperationException("Érvénytelen formátumú Moodle token érkezett.");
        }
        logger.LogInformation("Step 6: Successfully extracted token {TokenPrefix}...", wsToken[..6]);

        // 7. Fetch user info using core_webservice_get_site_info
        FormUrlEncodedContent siteInfoContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "wstoken", wsToken },
            { "wsfunction", "core_webservice_get_site_info" },
            { "moodlewsrestformat", "json" }
        });
        HttpResponseMessage siteInfoResp = await client.PostAsync($"{MoodleBase}/webservice/rest/server.php", siteInfoContent);
        SiteInfoDto? siteInfoJson = await siteInfoResp.Content.ReadFromJsonAsync<SiteInfoDto>();

        // 8. Optionally retrieve LTI launch token for softeng-hw portal
        string? ltik = await TryExtractLtiTokenAsync(client);

        return new LoginResponseDto(
            Token: wsToken,
            UserId: siteInfoJson?.UserId ?? 0,
            FullName: siteInfoJson?.FullName ?? username,
            Username: siteInfoJson?.Username ?? username,
            Ltik: ltik
        );
    }

    private async Task<string?> TryExtractLtiTokenAsync(HttpClient client)
    {
        try
        {
            logger.LogInformation("Step 8: Attempting to retrieve LTI token for module 221136");

            string[] startUrls = new[]
            {
                $"{MoodleBase}/mod/lti/launch.php?id=221136",
                $"{MoodleBase}/mod/lti/view.php?id=221136&forceview=1"
            };

            foreach (string? startUrl in startUrls)
            {
                (HttpResponseMessage? resp, string? capturedLtik) = await GetWithRedirectsAsync(client, startUrl);
                if (!string.IsNullOrEmpty(capturedLtik))
                {
                    logger.LogInformation("LTI: Captured ltik from initial GET redirect: {Ltik}", capturedLtik[..Math.Min(capturedLtik.Length, 20)]);
                    return capturedLtik;
                }

                string html = await resp.Content.ReadAsStringAsync();
                string? loc = GetLocation(resp);
                if (!string.IsNullOrEmpty(loc) && loc.Contains("ltik="))
                {
                    return ExtractLtikFromUrl(loc);
                }
                Match m = Regex.Match(html, @"ltik=([A-Za-z0-9_.\-]+)");
                if (m.Success)
                {
                    logger.LogInformation("LTI: Found ltik in start page HTML");
                    return m.Groups[1].Value;
                }

                // Check for iframe
                string iframeSrc = MatchGroup(html, @"<iframe[^>]*src=""([^""]+)""");
                if (!string.IsNullOrEmpty(iframeSrc))
                {
                    if (!iframeSrc.StartsWith("http")) iframeSrc = new Uri(new Uri(MoodleBase), WebUtility.HtmlDecode(iframeSrc)).ToString();
                    logger.LogInformation("LTI: Following iframe to {IframeSrc}", iframeSrc);
                    (HttpResponseMessage Response, string? CapturedLtik) iframeRes = await GetWithRedirectsAsync(client, iframeSrc);
                    if (!string.IsNullOrEmpty(iframeRes.CapturedLtik)) return iframeRes.CapturedLtik;
                    resp = iframeRes.Response;
                    html = await resp.Content.ReadAsStringAsync();
                    loc = GetLocation(resp);
                    if (!string.IsNullOrEmpty(loc) && loc.Contains("ltik="))
                    {
                        return ExtractLtikFromUrl(loc);
                    }
                }

                // Follow auto-submitting forms (LTI launch / OIDC)
                for (int hop = 0; hop < 5; hop++)
                {
                    string formAction = WebUtility.HtmlDecode(MatchGroup(html, @"<form[^>]*action=""([^""]+)"""));
                    if (string.IsNullOrEmpty(formAction)) break;

                    if (!formAction.StartsWith("http"))
                    {
                        formAction = new Uri(new Uri(MoodleBase), formAction).ToString();
                    }

                    logger.LogInformation("LTI: Submitting form hop {Hop} to {Action}", hop, formAction);
                    Dictionary<string, string> formData = new Dictionary<string, string>();
                    MatchCollection inputMatches = Regex.Matches(html, @"<input[^>]+>");
                    foreach (Match inp in inputMatches)
                    {
                        string tag = inp.Value;
                        string name = MatchGroup(tag, @"name=""([^""]+)""");
                        string val = WebUtility.HtmlDecode(MatchGroup(tag, @"value=""([^""]*)"""));
                        if (!string.IsNullOrEmpty(name))
                        {
                            formData[name] = val;
                        }
                    }

                    (HttpResponseMessage? postResp, string? postCapturedLtik) = await PostWithRedirectsAsync(client, formAction, new FormUrlEncodedContent(formData));
                    if (!string.IsNullOrEmpty(postCapturedLtik))
                    {
                        logger.LogInformation("LTI: Successfully captured ltik during POST hop {Hop} redirect!", hop);
                        return postCapturedLtik;
                    }

                    string? postLoc = GetLocation(postResp);
                    if (!string.IsNullOrEmpty(postLoc) && postLoc.Contains("ltik="))
                    {
                        logger.LogInformation("LTI: Successfully captured ltik from post redirect!");
                        return ExtractLtikFromUrl(postLoc);
                    }

                    html = await postResp.Content.ReadAsStringAsync();
                    m = Regex.Match(html, @"ltik=([A-Za-z0-9_.\-]+)");
                    if (m.Success)
                    {
                        logger.LogInformation("LTI: Successfully captured ltik from response HTML!");
                        return m.Groups[1].Value;
                    }
                    resp = postResp;
                }
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning("Optional LTI token retrieval failed (non-blocking): {Msg}", ex.Message);
        }
        return null;
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

    private static async Task<(HttpResponseMessage Response, string? CapturedLtik)> GetWithRedirectsAsync(HttpClient client, string url, int maxRedirects = 5)
    {
        string? capturedLtik = null;
        for (int i = 0; i < maxRedirects; i++)
        {
            if (url.Contains("ltik="))
            {
                capturedLtik = ExtractLtikFromUrl(url);
                return (await client.GetAsync(url), capturedLtik);
            }
            HttpResponseMessage resp = await client.GetAsync(url);
            string? loc = GetLocation(resp);
            if (!string.IsNullOrEmpty(loc) && loc.Contains("ltik="))
            {
                capturedLtik = ExtractLtikFromUrl(loc);
                return (resp, capturedLtik);
            }
            if ((int)resp.StatusCode >= 300 && (int)resp.StatusCode <= 399 && !string.IsNullOrEmpty(loc))
            {
                url = loc.StartsWith("http") ? loc : new Uri(new Uri(url), loc).ToString();
                continue;
            }
            return (resp, capturedLtik);
        }
        return (await client.GetAsync(url), capturedLtik);
    }

    private static async Task<(HttpResponseMessage Response, string? CapturedLtik)> PostWithRedirectsAsync(HttpClient client, string url, HttpContent content, int maxRedirects = 5)
    {
        HttpResponseMessage resp = await client.PostAsync(url, content);
        string? capturedLtik = null;
        for (int i = 0; i < maxRedirects; i++)
        {
            string? loc = GetLocation(resp);
            if (!string.IsNullOrEmpty(loc) && loc.Contains("ltik="))
            {
                capturedLtik = ExtractLtikFromUrl(loc);
                return (resp, capturedLtik);
            }
            if ((int)resp.StatusCode >= 300 && (int)resp.StatusCode <= 399 && !string.IsNullOrEmpty(loc))
            {
                url = loc.StartsWith("http") ? loc : new Uri(new Uri(url), loc).ToString();
                if (url.Contains("ltik="))
                {
                    capturedLtik = ExtractLtikFromUrl(url);
                    return (resp, capturedLtik);
                }
                resp = await client.GetAsync(url);
                continue;
            }
            break;
        }
        return (resp, capturedLtik);
    }

    private static string MatchGroup(string input, string pattern)
    {
        Match m = Regex.Match(input, pattern, RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value : string.Empty;
    }

    private class SiteInfoDto
    {
        [System.Text.Json.Serialization.JsonPropertyName("userid")]
        public int UserId { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("fullname")]
        public string? FullName { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("username")]
        public string? Username { get; set; }
    }
}
