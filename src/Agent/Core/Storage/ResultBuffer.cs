using System.IO.Compression;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using WebScan.Contracts;

namespace WebScan.Agent.Storage;

public sealed record BufferedBatch(Guid BatchId, Guid JobId, Guid LeaseId, int Sequence, byte[] GzipPayload, int Attempts);

public enum FinalKind { Complete, Fail }

public sealed record PendingFinal(Guid JobId, Guid LeaseId, FinalKind Kind, string Payload);

/// <summary>
/// Durable local buffer (SQLite in <c>Agent:DataDirectory</c>): unsent result batches (gzip JSON, exactly as uploaded) and the
/// state of jobs whose final complete/fail call has not been acknowledged yet. Survives restarts and server outages.
/// </summary>
public sealed class ResultBuffer
{
    private readonly string _connectionString;
    private readonly TimeProvider _time;

    public ResultBuffer(IOptions<AgentOptions> options, TimeProvider time)
    {
        _time = time;
        var dir = AgentPaths.DataDirectory(options.Value);
        Directory.CreateDirectory(dir);
        _connectionString = new SqliteConnectionStringBuilder { DataSource = Path.Combine(dir, "agent-buffer.db"), Pooling = false }.ToString();
        using var c = Open();
        Execute(c, """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS batches(
                batch_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, lease_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                payload BLOB NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS ix_batches_job ON batches(job_id, sequence);
            CREATE TABLE IF NOT EXISTS jobs(
                job_id TEXT PRIMARY KEY, lease_id TEXT NOT NULL, state TEXT NOT NULL, batch_count INTEGER NOT NULL DEFAULT 0,
                final_kind TEXT, final_payload TEXT, updated_at TEXT NOT NULL);
            """);
    }

    public static byte[] Compress(ScanResultBatch batch)
    {
        using var ms = new MemoryStream();
        using (var gzip = new GZipStream(ms, CompressionLevel.Fastest, leaveOpen: true))
            JsonSerializer.Serialize(gzip, batch, ContractJson.Options);
        return ms.ToArray();
    }

    public static ScanResultBatch Decompress(byte[] payload)
    {
        using var gzip = new GZipStream(new MemoryStream(payload), CompressionMode.Decompress);
        return JsonSerializer.Deserialize<ScanResultBatch>(gzip, ContractJson.Options)!;
    }

    public void StartJob(Guid jobId, Guid leaseId)
    {
        using var c = Open();
        Execute(c, "INSERT OR REPLACE INTO jobs(job_id, lease_id, state, batch_count, updated_at) VALUES ($job, $lease, 'running', 0, $now)",
            ("$job", jobId.ToString()), ("$lease", leaseId.ToString()), ("$now", Now()));
    }

    /// <summary>Stores a batch; returns false when the job is unknown (dropped, e.g. stale lease).</summary>
    public bool AddBatch(ScanResultBatch batch)
    {
        using var c = Open();
        using var tx = c.BeginTransaction();
        var updated = Execute(c, "UPDATE jobs SET batch_count = batch_count + 1, updated_at = $now WHERE job_id = $job AND lease_id = $lease",
            ("$job", batch.JobId.ToString()), ("$lease", batch.LeaseId.ToString()), ("$now", Now()));
        if (updated == 0) return false;
        Execute(c, "INSERT INTO batches(batch_id, job_id, lease_id, sequence, payload, created_at) VALUES ($id, $job, $lease, $seq, $payload, $now)",
            ("$id", batch.BatchId.ToString()), ("$job", batch.JobId.ToString()), ("$lease", batch.LeaseId.ToString()),
            ("$seq", batch.Sequence), ("$payload", Compress(batch)), ("$now", Now()));
        tx.Commit();
        return true;
    }

    public void SetFinal(Guid jobId, FinalKind kind, string payload)
    {
        using var c = Open();
        Execute(c, "UPDATE jobs SET state = 'finishing', final_kind = $kind, final_payload = $payload, updated_at = $now WHERE job_id = $job",
            ("$job", jobId.ToString()), ("$kind", kind.ToString()), ("$payload", payload), ("$now", Now()));
    }

    public int BatchCount(Guid jobId)
    {
        using var c = Open();
        return Convert.ToInt32(Scalar(c, "SELECT batch_count FROM jobs WHERE job_id = $job", ("$job", jobId.ToString())) ?? 0);
    }

    public bool HasJob(Guid jobId)
    {
        using var c = Open();
        return Scalar(c, "SELECT 1 FROM jobs WHERE job_id = $job", ("$job", jobId.ToString())) is not null;
    }

    public IReadOnlyList<BufferedBatch> PendingBatches(int limit)
    {
        using var c = Open();
        using var cmd = Command(c, "SELECT batch_id, job_id, lease_id, sequence, payload, attempts FROM batches ORDER BY rowid LIMIT $limit", ("$limit", limit));
        using var r = cmd.ExecuteReader();
        var list = new List<BufferedBatch>();
        while (r.Read())
            list.Add(new BufferedBatch(Guid.Parse(r.GetString(0)), Guid.Parse(r.GetString(1)), Guid.Parse(r.GetString(2)), r.GetInt32(3), (byte[])r[4], r.GetInt32(5)));
        return list;
    }

    public int PendingBatchCount()
    {
        using var c = Open();
        return Convert.ToInt32(Scalar(c, "SELECT COUNT(*) FROM batches"));
    }

    public void DeleteBatch(Guid batchId)
    {
        using var c = Open();
        Execute(c, "DELETE FROM batches WHERE batch_id = $id", ("$id", batchId.ToString()));
    }

    public void IncrementAttempts(Guid batchId)
    {
        using var c = Open();
        Execute(c, "UPDATE batches SET attempts = attempts + 1 WHERE batch_id = $id", ("$id", batchId.ToString()));
    }

    /// <summary>Jobs whose final call can be sent: all their batches are acknowledged.</summary>
    public IReadOnlyList<PendingFinal> PendingFinals()
    {
        using var c = Open();
        using var cmd = Command(c, """
            SELECT j.job_id, j.lease_id, j.final_kind, j.final_payload FROM jobs j
            WHERE j.state = 'finishing' AND NOT EXISTS (SELECT 1 FROM batches b WHERE b.job_id = j.job_id) ORDER BY j.updated_at
            """);
        using var r = cmd.ExecuteReader();
        var list = new List<PendingFinal>();
        while (r.Read()) list.Add(new PendingFinal(Guid.Parse(r.GetString(0)), Guid.Parse(r.GetString(1)), Enum.Parse<FinalKind>(r.GetString(2)), r.GetString(3)));
        return list;
    }

    /// <summary>Jobs left 'running' by a previous process (crash/kill): (jobId, leaseId, batchCount).</summary>
    public IReadOnlyList<(Guid JobId, Guid LeaseId, int BatchCount)> InterruptedJobs()
    {
        using var c = Open();
        using var cmd = Command(c, "SELECT job_id, lease_id, batch_count FROM jobs WHERE state = 'running'");
        using var r = cmd.ExecuteReader();
        var list = new List<(Guid, Guid, int)>();
        while (r.Read()) list.Add((Guid.Parse(r.GetString(0)), Guid.Parse(r.GetString(1)), r.GetInt32(2)));
        return list;
    }

    /// <summary>Removes a job and all its unsent batches (final call acknowledged, or lease stale).</summary>
    public void RemoveJob(Guid jobId)
    {
        using var c = Open();
        using var tx = c.BeginTransaction();
        Execute(c, "DELETE FROM batches WHERE job_id = $job", ("$job", jobId.ToString()));
        Execute(c, "DELETE FROM jobs WHERE job_id = $job", ("$job", jobId.ToString()));
        tx.Commit();
    }

    private SqliteConnection Open()
    {
        var c = new SqliteConnection(_connectionString);
        c.Open();
        return c;
    }

    private string Now() => _time.GetUtcNow().ToString("O");

    private static SqliteCommand Command(SqliteConnection c, string sql, params (string Name, object Value)[] parameters)
    {
        var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (name, value) in parameters) cmd.Parameters.AddWithValue(name, value);
        return cmd;
    }

    private static int Execute(SqliteConnection c, string sql, params (string Name, object Value)[] parameters)
    {
        using var cmd = Command(c, sql, parameters);
        return cmd.ExecuteNonQuery();
    }

    private static object? Scalar(SqliteConnection c, string sql, params (string Name, object Value)[] parameters)
    {
        using var cmd = Command(c, sql, parameters);
        return cmd.ExecuteScalar();
    }
}
