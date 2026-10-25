using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Backend.Filters;

public partial class GlobalExceptionFilter(ILogger<GlobalExceptionFilter> logger) : IExceptionFilter
{
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

            logger.LogWarning("Upstream request timed out: {Message}", context.Exception.Message);
            context.Result = new ObjectResult(new { error = "A külső szerver nem válaszolt időben." })
            {
                StatusCode = StatusCodes.Status504GatewayTimeout
            };
            context.ExceptionHandled = true;
            return;
        }

        LogExceptionCaught(logger, context.Exception, context.Exception.Message);

        context.Result = context.Exception switch
        {
            UnauthorizedAccessException => new UnauthorizedResult(),
            ValidationException validationEx => new BadRequestObjectResult(new { error = validationEx.Message }),
            KeyNotFoundException => new NotFoundResult(),
            ArgumentException or InvalidOperationException => new BadRequestResult(),
            _ => new StatusCodeResult(StatusCodes.Status500InternalServerError)
        };

        context.ExceptionHandled = true;
    }
}
