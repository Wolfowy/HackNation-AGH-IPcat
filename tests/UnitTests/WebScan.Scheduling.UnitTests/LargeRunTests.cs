using System.Diagnostics;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WebScan.Contracts;
using WebScan.Scheduling.UnitTests.Support;
using WebScan.Server.Kernel.Networking;
using WebScan.Server.Modules.Scanning.Persistence;
using Xunit.Abstractions;

namespace WebScan.Scheduling.UnitTests;

[Collection(DbCollection.Name)]
public sealed class LargeRunTests(TestHost host, ITestOutputHelper output) : DbTestBase(host)
{
    [Fact]
    public async Task Sixteen_thousand_addresses_flow_through_the_database_queue_without_gaps_or_duplicates()
    {
        var net = Host.Scope.Add(Zone, ["10.80.0.0/18"], ["10.80.10.0/24"]);
        var agents = Enumerable.Range(1, 4).Select(i => $"bulk-{Zone}-{i}").ToList();
        foreach (var a in agents) Host.Agents.Set(Agents.Simple(a, Zone, "10.80.0.0/16", maxJobs: 8));

        var planning = Stopwatch.StartNew();
        var (runId, plan) = await QueueJobsAsync(net, batchSize: 64);
        planning.Stop();

        var execution = Stopwatch.StartNew();
        var processed = await Task.WhenAll(agents.Select(a => Host.DrainAsync(a, job =>
            IpRangeSet.Parse(job.Targets.Hosts).Ranges
                .SelectMany(r => Enumerable.Range(0, (int)r.Count).Where(i => i % 32 == 0).Select(i => IpRangeSet.ToAddress(r.Family, r.Start + (UInt128)i).ToString()))
                .Select(address => Observations.Make(job.JobId, ObservationKind.HostUp, address, agentId: a)).ToList(), maxRounds: 1000)));
        execution.Stop();

        Assert.Equal(252, plan.JobsCreated);
        Assert.Equal(plan.JobsCreated, processed.Sum());
        Assert.All(processed, p => Assert.True(p > 0, "every agent took part"));

        var jobs = await Host.DbAsync(db => db.Jobs.AsNoTracking().Where(j => j.ScanRunId == runId).ToListAsync());
        Assert.All(jobs, j => Assert.Equal(JobStatus.Completed, j.Status));
        Assert.All(jobs, j => Assert.Equal(1, j.Attempt));
        var targets = jobs.Select(j => IpRangeSet.Parse(JsonSerializer.Deserialize<ScanJob>(j.PayloadJson, ContractJson.Options)!.Targets.Hosts)).ToList();
        var union = targets.Aggregate(new IpRangeSet(), (acc, s) => acc.Union(s));
        Assert.Equal(IpRangeSet.Parse(["10.80.0.0/18"]).Subtract(IpRangeSet.Parse(["10.80.10.0/24"])).ToString(), union.ToString());
        Assert.Equal((ulong)union.Count, (ulong)jobs.Sum(j => j.TargetCount)); // no address in two jobs
        Assert.Equal(jobs.Count, await Host.DbAsync(db => db.ResultBatches.CountAsync(b => b.ScanRunId == runId)));
        Assert.Equal(16_128 / 32, await Host.DbAsync(db => db.ResultBatches.Where(b => b.ScanRunId == runId).SumAsync(b => b.ObservationCount)));

        output.WriteLine($"{union.Count} addresses, {plan.JobsCreated} jobs: planned+queued in {planning.ElapsedMilliseconds} ms, " +
                         $"claimed/uploaded/completed by 4 agents over HTTP in {execution.ElapsedMilliseconds} ms ({string.Join(", ", processed)} jobs per agent)");
    }
}
