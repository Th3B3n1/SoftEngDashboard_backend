using System.ComponentModel.DataAnnotations;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Backend.Filters;

public partial class GlobalExceptionFilter(ILogger<GlobalExceptionFilter> logger) : IExceptionFilter
{
    private readonly ILogger<GlobalExceptionFilter> _logger = logger;

    [LoggerMessage(EventId = 1, Level = LogLevel.Error, Message = "Exception caught by GlobalExceptionFilter: {ErrorMessage}")]
    private static partial void LogExceptionCaught(ILogger logger, Exception ex, string errorMessage);

    public void OnException(ExceptionContext context)
    {
        if (context.Exception is OperationCanceledException)
        {
            if (context.HttpContext.RequestAborted.IsCancellationRequested)
            {
                context.Result = new StatusCodeResult(499);
                context.ExceptionHandled = true;
                return;
            }

            _logger.LogWarning("Upstream request timed out: {Message}", context.Exception.Message);
            context.Result = new ObjectResult(new { error = "A külső szerver nem válaszolt időben." })
            {
                StatusCode = StatusCodes.Status504GatewayTimeout
            };
            context.ExceptionHandled = true;
            return;
        }

        LogExceptionCaught(_logger, context.Exception, context.Exception.Message);

        switch (context.Exception)
        {
            case UnauthorizedAccessException:
                context.Result = new UnauthorizedResult();
                break;

            case ValidationException validationEx:
                context.Result = new BadRequestObjectResult(new { error = validationEx.Message });
                break;

            case KeyNotFoundException:
                context.Result = new NotFoundResult();
                break;

            case ArgumentException:
            case InvalidOperationException:
                context.Result = new BadRequestResult();
                break;

            default:
                context.Result = new StatusCodeResult(StatusCodes.Status500InternalServerError);
                break;
        }

        context.ExceptionHandled = true;
    }
}
