using Backend.DTOs;
using Backend.Services;
using Microsoft.AspNetCore.Mvc;

namespace Backend.Controllers;

[ApiController]
[Route("api/hf")]
public class HfController(
    HfPortalService hfPortalService) : ControllerBase
{
    private readonly HfPortalService _hfPortalService = hfPortalService;

    /// <summary>
    /// Proxies the student's HF Portal status using the extracted LTI token.
    /// </summary>
    [HttpGet("status")]
    public async Task<IActionResult> GetStatus([FromQuery] HfStatusRequestDto query, CancellationToken ct)
    {
        var result = await _hfPortalService.GetStatusAsync(query.Ltik, ct);
        return Ok(result);
    }
}

