using System.Text.Json.Nodes;

using Microsoft.AspNetCore.Mvc;

using Backend.DTOs;
using Backend.Services;

namespace Backend.Controllers;

[ApiController]
[Route("api/hf")]
public class HfController(
    HfPortalService hfPortalService,
    MoodleAuthService moodleAuthService) : ControllerBase
{
    private readonly HfPortalService _hfPortalService = hfPortalService;
    private readonly MoodleAuthService _moodleAuthService = moodleAuthService;

    /// <summary>
    /// Proxies the student's HF Portal status using the extracted LTI token.
    /// </summary>
    [HttpGet("status")]
    public async Task<IActionResult> GetStatus([FromQuery] HfStatusRequestDto query, CancellationToken ct)
    {
        JsonObject result = await _hfPortalService.GetStatusAsync(query.Ltik, ct);
        return Ok(result);
    }

    /// <summary>
    /// Uses the student's Moodle mobile token (wstoken) to obtain an LTI launch token via
    /// Moodle web services and fetch their HF Portal status.
    /// </summary>
    [HttpPost("sync-by-moodle-token")]
    public async Task<IActionResult> SyncByMoodleToken([FromBody] HfSyncByMoodleTokenRequestDto req, CancellationToken ct)
    {
        string? ltik = await _moodleAuthService.ExtractLtiTokenFromWsTokenAsync(req.WsToken, ct);
        if (string.IsNullOrWhiteSpace(ltik))
        {
            return NotFound(new { error = "A Házi Feladat Portál nem érhető el közvetlenül a szerverről, vagy az LTI indítás nem sikerült." });
        }

        JsonObject status = await _hfPortalService.GetStatusAsync(ltik, ct);
        return Ok(new { ltik, status });
    }
}

