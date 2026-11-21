using Microsoft.Extensions.DependencyInjection;
using WebScan.Contracts;
using WebScan.Server.Modules.Scanning.Persistence;
using WebScan.Server.Modules.Scanning.Planning;
using WebScan.Server.Modules.Scanning.Runs;

namespace WebScan.Scheduling.UnitTests.Support;

[Collection(DbCollection.Name)]
public abstract class DbTestBase(TestHost host) : IAsyncLifetime
{
    protected TestHost Host { get; } = host;

    /// <summary>Unique zone per test: agents of one test never claim jobs of another.</summary>
    protected string Zone { get; } = $"z-{Guid.NewGuid():N}"[..12];

    public virtual Task InitializeAsync() => Host.ResetQueueAsync();
    public virtual Task DisposeAsync() => Task.CompletedTask;

    /// <summary>Creates a scan run directly (no workflow) and queues jobs for one agent step.</summary>
    protected async Task<(Guid RunId, PlanResult Plan)> QueueJobsAsync(Guid networkId, ScanOperation operation = ScanOperation.DiscoverHosts,
        int maxAttempts = 3, int backoffSeconds = 0, int? batchSize = null, IReadOnlyCollection<ScanEndpoint>? endpoints = null, int priority = 50,
        int timeoutSeconds = 600)
    {
        var runId = Guid.NewGuid();
        var plan = await Host.WithScopeAsync(async sp =>
        {
            await sp.GetRequiredService<ScanRunStore>().CreateAsync(new ScanRun
            {
                Id = runId, Name = "test", Status = ScanRunStatus.Running, WorkflowKey = "none", WorkflowVersion = 1, NetworkIds = [networkId],
                TriggeredBy = "test", CreatedAt = Host.Time.GetUtcNow(), Priority = priority,
            });
            return await sp.GetRequiredService<TaskPlanner>().PlanAsync(new AgentStepSpec
            {
                ScanRunId = runId, StepId = "step", Operation = operation, NetworkIds = [networkId], MaxAttempts = maxAttempts,
                BackoffSeconds = backoffSeconds, BatchSize = batchSize, Endpoints = endpoints, Priority = priority, TimeoutSeconds = timeoutSeconds,
                Parameters = ParameterValidator.Validate(OperationCatalog.Get(operation).Parameters, null).Values,
            });
        });
        return (runId, plan);
    }
}
