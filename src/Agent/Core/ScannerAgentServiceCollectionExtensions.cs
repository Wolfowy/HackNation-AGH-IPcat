using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Options;
using Polly;
using WebScan.Agent.Communication;
using WebScan.Agent.Execution;
using WebScan.Agent.Inventory;
using WebScan.Agent.Storage;
using WebScan.Agent.Tools;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Agent.Tools.Adapters;
using WebScan.Agent.Tools.Parsers;
using WebScan.Contracts;

namespace WebScan.Agent;

public static class ScannerAgentServiceCollectionExtensions
{
    /// <summary>
    /// Registers the complete scanner agent (tools, execution, buffer, server communication, hosted worker).
    /// <paramref name="configureHttp"/> customizes the server HttpClient, e.g. in-process E2E tests:
    /// <c>b => b.ConfigurePrimaryHttpMessageHandler(() => factory.Server.CreateHandler())</c>.
    /// </summary>
    public static IServiceCollection AddScannerAgent(this IServiceCollection services, IConfiguration configuration, Action<IHttpClientBuilder>? configureHttp = null)
    {
        var section = configuration.GetSection(AgentOptions.Section);
        services.AddOptions<AgentOptions>().Bind(section).Validate(o => o.MaxConcurrentJobs >= 1 && o.MaxRatePerSecond >= 1, "Agent:MaxConcurrentJobs and Agent:MaxRatePerSecond must be >= 1.");
        services.TryAddSingleton(TimeProvider.System);

        // Tools: built-in parsers/adapters (plugins are added to the registry at startup).
        services.AddSingleton<IToolOutputParser, NmapXmlParser>();
        services.AddSingleton<IToolOutputParser, NaabuJsonlParser>();
        services.AddSingleton<IToolOutputParser, HttpxJsonlParser>();
        services.AddSingleton<IToolOutputParser, NucleiJsonlParser>();
        services.AddSingleton<IToolOutputParser, GenericJsonlParser>();
        services.AddSingleton<IToolAdapter, ManifestToolAdapter>();
        if (section.GetValue<bool>(nameof(AgentOptions.EnableFakeTools))) services.AddSingleton<IToolAdapter, FakeScannerAdapter>();
        services.AddSingleton<ToolComponentRegistry>();
        services.AddSingleton<PluginLoader>();
        services.AddSingleton<ToolRegistry>();
        services.AddSingleton<IToolProcessRunner, ProcessRunner>();

        services.AddSingleton<NetworkInventory>();
        services.AddSingleton<CredentialStore>();
        services.AddSingleton<ResultBuffer>();
        services.AddSingleton<JobValidator>();
        services.AddSingleton<ToolExecutor>();
        services.AddSingleton<JobExecutor>();
        services.AddSingleton<AgentState>();
        services.AddSingleton<AgentRegistrar>();
        services.AddSingleton<ResultUploader>();
        services.AddHostedService<AgentWorker>();

        var http = services.AddHttpClient<AgentApiClient>((sp, client) =>
            {
                var o = sp.GetRequiredService<IOptions<AgentOptions>>().Value;
                client.BaseAddress = new Uri(o.ServerUrl);
                client.Timeout = Timeout.InfiniteTimeSpan; // per-attempt timeout is part of the resilience pipeline
            })
            .ConfigurePrimaryHttpMessageHandler(sp => CreateServerHandler(configuration, sp.GetRequiredService<IHostEnvironment>()));
        http.AddResilienceHandler("agent-api", (pipeline, context) =>
        {
            var o = context.ServiceProvider.GetRequiredService<IOptions<AgentOptions>>().Value;
            if (o.HttpRetryAttempts > 0)
                pipeline.AddRetry(new HttpRetryStrategyOptions
                {
                    MaxRetryAttempts = o.HttpRetryAttempts,
                    BackoffType = DelayBackoffType.Exponential,
                    UseJitter = true,
                    Delay = TimeSpan.FromMilliseconds(Math.Max(1, o.HttpRetryBaseDelayMs)),
                    // Default predicate: network errors, timeouts, 5xx, 408, 429 — never other 4xx. Rotation is not idempotent.
                    ShouldHandle = args => args.Context.GetRequestMessage()?.RequestUri?.AbsolutePath == AgentApiRoutes.RotateCredentials
                        ? PredicateResult.False()
                        : HttpClientResiliencePredicates.IsTransient(args.Outcome) ? PredicateResult.True() : PredicateResult.False(),
                });
            pipeline.AddTimeout(TimeSpan.FromSeconds(Math.Max(1, o.HttpTimeoutSeconds)));
        });
        configureHttp?.Invoke(http);
        return services;
    }

    /// <summary>System trust by default; <c>Server:CaCertificatePath</c> pins a private CA; <c>Server:AllowInsecureTls</c> only in Development.</summary>
    private static HttpMessageHandler CreateServerHandler(IConfiguration configuration, IHostEnvironment environment)
    {
        var handler = new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5), AutomaticDecompression = System.Net.DecompressionMethods.All };
        var caPath = configuration["Server:CaCertificatePath"];
        if (configuration.GetValue<bool>("Server:AllowInsecureTls"))
        {
            if (!environment.IsDevelopment()) throw new InvalidOperationException("Server:AllowInsecureTls is only allowed in the Development environment.");
            handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        }
        else if (!string.IsNullOrWhiteSpace(caPath))
        {
            var ca = X509CertificateLoader.LoadCertificateFromFile(caPath);
            handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
            {
                if (certificate is null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None) return false;
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(ca);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return chain.Build(new X509Certificate2(certificate));
            };
        }
        return handler;
    }
}
