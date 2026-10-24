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
    public async Task<ActionResult<LoginResponseDto>> Login([FromBody] LoginRequestDto request)
    {
        LoginResponseDto result = await _authService.LoginAsync(request.Username, request.Password);
        return Ok(result);
    }
}

