using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Backend.Filters;

public partial class GlobalExceptionFilter(ILogger<GlobalExceptionFilter> logger) : IExceptionFilter
{
    private readonly ILogger<GlobalExceptionFilter> _logger = logger;

    public void OnException(ExceptionContext context)
    {
        _logger.LogError(context.Exception, "Exception caught by GlobalExceptionFilter: {Message}", context.Exception.Message);

        switch (context.Exception)
        {
            case UnauthorizedAccessException:
                context.Result = new UnauthorizedObjectResult(new { error = context.Exception.Message });
                break;

            case ValidationException validationEx:
                context.Result = new BadRequestObjectResult(new { error = validationEx.Message });
                break;

            case KeyNotFoundException:
                context.Result = new NotFoundObjectResult(new { error = context.Exception.Message });
                break;

            case ArgumentException argumentEx:
                context.Result = new BadRequestObjectResult(new { error = argumentEx.Message });
                break;

            case InvalidOperationException invalidOpEx:
                context.Result = new BadRequestObjectResult(new { error = invalidOpEx.Message });
                break;

            default:
                context.Result = new ObjectResult(new { error = context.Exception.Message })
                {
                    StatusCode = StatusCodes.Status500InternalServerError
                };
                break;
        }

        context.ExceptionHandled = true;
    }
}

