using System.Reflection;
using JasperFx;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Kernel.Messaging;
using Wolverine;
using Wolverine.EntityFrameworkCore;
using Wolverine.Postgresql;
using Wolverine.RabbitMQ;

namespace WebScan.Server.Infrastructure.Messaging;

/// <summary>
/// Wolverine: handlers discovered in the module assemblies; envelope storage (inbox/outbox) in PostgreSQL schema
/// <c>wolverine</c>; EF Core transaction integration so modules can use <c>IDbContextOutbox&lt;TContext&gt;</c>.
/// Kernel messages travel through durable RabbitMQ queues when <c>RabbitMq:ConnectionString</c> is set,
/// otherwise through durable local queues.
/// </summary>
public static class MessagingSetup
{
    public const string WolverineSchema = "wolverine";

    /// <summary>Queue name per cross-module message (same names locally and in RabbitMQ).</summary>
    public static readonly IReadOnlyDictionary<Type, string> KernelQueues = new Dictionary<Type, string>
    {
        [typeof(ScanResultBatchReceived)] = "webscan.scan-result-batch-received",
        [typeof(ScanJobFinished)] = "webscan.scan-job-finished",
        [typeof(AgentWentOffline)] = "webscan.agent-went-offline",
        [typeof(ScanRunFinished)] = "webscan.scan-run-finished",
        [typeof(AssetChangesDetected)] = "webscan.asset-changes-detected",
    };

    public static IHostApplicationBuilder AddWebScanMessaging(this IHostApplicationBuilder builder, IEnumerable<Assembly> handlerAssemblies)
    {
        var configuration = builder.Configuration;
        // Unit tests without a database may set Wolverine:PersistMessages=false (no inbox/outbox, no IDbContextOutbox).
        var persist = configuration.GetValue("Wolverine:PersistMessages", true);
        var rabbitMq = configuration["RabbitMq:ConnectionString"];
        var assemblies = handlerAssemblies.ToList();

        builder.UseWolverine(opts =>
        {
            opts.ServiceName = configuration["OpenTelemetry:ServiceName"] ?? "webscan-server";
            opts.UseRuntimeCompilation(); // handler code is generated and compiled at startup (no pre-generated code to keep in sync)
            if (assemblies.Count > 0) opts.ApplicationAssembly = assemblies[0];
            foreach (var assembly in assemblies) opts.Discovery.IncludeAssembly(assembly);

            if (Enum.TryParse<DurabilityMode>(configuration["Wolverine:DurabilityMode"], ignoreCase: true, out var mode))
                opts.Durability.Mode = mode;

            if (persist)
            {
                opts.PersistMessagesWithPostgresqlUsingNamedConnection(ModuleDbContextExtensions.ConnectionStringName, WolverineSchema);
                opts.AutoBuildMessageStorageOnStartup = AutoCreate.CreateOrUpdate;
                opts.UseEntityFrameworkCoreTransactions();
                opts.Policies.UseDurableLocalQueues();
                opts.Policies.UseDurableInboxOnAllListeners();
                opts.Policies.UseDurableOutboxOnAllSendingEndpoints();
            }

            if (!string.IsNullOrWhiteSpace(rabbitMq))
            {
                opts.UseRabbitMq(new Uri(rabbitMq)).AutoProvision();
                foreach (var (type, queue) in KernelQueues)
                {
                    opts.Publish(p => p.Message(type).ToRabbitQueue(queue));
                    opts.ListenToRabbitQueue(queue);
                }
            }
            else
            {
                foreach (var (type, queue) in KernelQueues)
                    opts.Publish(p => p.Message(type).ToLocalQueue(queue));
            }
        });
        return builder;
    }
}
