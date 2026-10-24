using System.IO.Compression;
using System.Threading.RateLimiting;

using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.ResponseCompression;

using Backend.Filters;
using Backend.Services;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers(options =>
{
    options.Filters.Add<GlobalExceptionFilter>();
});

builder.Services.AddHttpClient("HfPortal", client =>
{
    client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36");
    client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
    client.DefaultRequestHeaders.Add("Referer", "https://softeng-hw.ftsrg.org/");
});
builder.Services.AddSingleton<MoodleAuthService>();
builder.Services.AddScoped<HfPortalService>();

string[] allowedOrigins = Environment.GetEnvironmentVariable("FRONTEND_URL")?.Split(';')
    ?? ["http://localhost:5173", "http://localhost:5174", "http://localhost:5228", "https://localhost:7203"];

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy
            .WithMethods("GET", "POST", "OPTIONS")
            .WithHeaders("Content-Type")
            .WithOrigins(allowedOrigins);
    });
});


builder.Services.AddResponseCompression(options =>
{
    options.EnableForHttps = true;
    options.Providers.Add<BrotliCompressionProvider>();
    options.Providers.Add<GzipCompressionProvider>();
});
builder.Services.Configure<BrotliCompressionProviderOptions>(options =>
{
    options.Level = CompressionLevel.Fastest;
});

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
    {
        string? forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        string clientIp = !string.IsNullOrEmpty(forwardedFor)
            ? forwardedFor.Split(',')[0].Trim()
            : httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown-ip";

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: clientIp,
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 60,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
                AutoReplenishment = true
            });
    });

    // Stricter rate limit for authentication endpoint to prevent brute-force attacks
    options.AddFixedWindowLimiter("auth", limiterOptions =>
    {
        limiterOptions.PermitLimit = 10;
        limiterOptions.Window = TimeSpan.FromMinutes(1);
        limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        limiterOptions.QueueLimit = 0;
        limiterOptions.AutoReplenishment = true;
    });
});

WebApplication app = builder.Build();

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

app.UseResponseCompression();

// Security headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    await next();
});

app.UseCors();
app.UseRateLimiter();

app.MapControllers();

app.Run();
