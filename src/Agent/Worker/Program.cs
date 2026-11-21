// TODO(Agent B): host composition (AddScannerAgent), configuration, tool manifests, plugins.
var builder = Host.CreateApplicationBuilder(args);
var host = builder.Build();
host.Run();
