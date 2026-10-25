using Backend.Services;
using Microsoft.AspNetCore.Mvc;

namespace Backend.Controllers;

[ApiController]
[Route("api/moodle")]
public class MoodleController(MoodleProxyService proxyService) : ControllerBase
{
    private readonly MoodleProxyService _proxyService = proxyService;

    /// <summary>
    /// Proxies Moodle Web Service calls after decrypting the server-protected token,
    /// enforcing a strict read-only function allowlist and Course 16995 scope.
    /// </summary>
    [HttpPost("ws")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> CallWebService(CancellationToken ct)
    {
        if (!Request.HasFormContentType)
        {
            return BadRequest(new { exception = "moodle_exception", errorcode = "invalidparameter", message = "Form content required." });
        }

        IFormCollection form = await Request.ReadFormAsync(ct);
        (int statusCode, string contentJson) = await _proxyService.ExecuteReadOnlyCourseCallAsync(form, ct);
        return new ContentResult
        {
            StatusCode = statusCode,
            Content = contentJson,
            ContentType = "application/json; charset=utf-8"
        };
    }
}

