using Backend.DTOs;
using Backend.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Backend.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController(
    MoodleAuthService authService) : ControllerBase
{
    private readonly MoodleAuthService _authService = authService;

    /// <summary>
    /// Authenticates a user against BME IdP / Shibboleth Moodle and extracts a token.
    /// Rate-limited to 10 requests per minute to prevent brute-force attacks.
    /// </summary>
    [HttpPost("login")]
    [EnableRateLimiting("auth")]
    public async Task<ActionResult<LoginResponseDto>> Login([FromBody] LoginRequestDto request, CancellationToken ct)
    {
        LoginResponseDto result = await _authService.LoginAsync(request.Username, request.Password, ct);
        return Ok(result);
    }

    /// <summary>
    /// Encrypts a raw 32-character Moodle token into a server-bound AES-256-GCM token
    /// so the raw Moodle token never needs to be stored in the browser.
    /// </summary>
    [HttpPost("protect-token")]
    public IActionResult ProtectToken([FromBody] ProtectTokenRequestDto request)
    {
        string? raw = MoodleTokenCrypto.Unprotect(request.Token);
        if (string.IsNullOrEmpty(raw))
        {
            return BadRequest(new { error = "Érvénytelen Moodle token." });
        }

        string protectedToken = MoodleTokenCrypto.Protect(raw);
        return Ok(new { token = protectedToken });
    }
}

