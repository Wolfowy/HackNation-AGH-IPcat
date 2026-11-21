using WebScan.Agent;

// Operator commands (handled before the host runs; stripped from the configuration arguments):
//   --list-tools            probe tool manifests and print the registry
//   --run-job <job.json>    execute one ScanJob locally and print observations as JSON lines (no server)
var listTools = args.Contains("--list-tools");
var runJobIndex = Array.IndexOf(args, "--run-job");
var jobFile = runJobIndex >= 0 && runJobIndex + 1 < args.Length ? args[runJobIndex + 1] : null;
var configArgs = args.Where((a, i) => a != "--list-tools" && i != runJobIndex && (runJobIndex < 0 || i != runJobIndex + 1)).ToArray();

var builder = Host.CreateApplicationBuilder(configArgs);
if (listTools || runJobIndex >= 0) // keep stdout clean for command output
    builder.Services.Configure<Microsoft.Extensions.Logging.Console.ConsoleLoggerOptions>(o => o.LogToStandardErrorThreshold = LogLevel.Trace);
builder.Services.AddScannerAgent(builder.Configuration);
using var host = builder.Build();

if (listTools) return await AgentCommands.ListToolsAsync(host.Services, Console.Out);
if (runJobIndex >= 0)
{
    if (jobFile is null) { Console.Error.WriteLine("Usage: --run-job <job.json>"); return 2; }
    return await AgentCommands.RunJobAsync(host.Services, jobFile, Console.Out, Console.Error);
}

await host.RunAsync();
return 0;
