using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using WebScan.Server.Kernel.Telemetry;

namespace WebScan.Server.Infrastructure.Telemetry;

public static class TelemetrySetup
{
    /// <summary>Traces + metrics (and logs) via OpenTelemetry; exported over OTLP/gRPC when <c>OpenTelemetry:OtlpEndpoint</c> is set.</summary>
    public static IHostApplicationBuilder AddWebScanTelemetry(this IHostApplicationBuilder builder)
    {
        var configuration = builder.Configuration;
        var otel = builder.Services.AddOpenTelemetry()
            .ConfigureResource(r => r.AddService(configuration["OpenTelemetry:ServiceName"] ?? "webscan-server"))
            .WithTracing(t => t
                .AddSource(WebScanTelemetry.Name, "Npgsql", "Wolverine")
                .AddAspNetCoreInstrumentation(o => o.Filter = ctx => !ctx.Request.Path.StartsWithSegments("/health"))
                .AddHttpClientInstrumentation())
            .WithMetrics(m => m
                .AddMeter(WebScanTelemetry.Name, "Npgsql", "Wolverine*")
                .AddAspNetCoreInstrumentation()
                .AddRuntimeInstrumentation());

        var endpoint = configuration["OpenTelemetry:OtlpEndpoint"];
        if (!string.IsNullOrWhiteSpace(endpoint))
            otel.WithLogging().UseOtlpExporter(OtlpExportProtocol.Grpc, new Uri(endpoint));

        return builder;
    }
}
