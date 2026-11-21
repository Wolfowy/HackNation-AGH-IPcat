namespace WebScan.Server.Kernel.Scanning;

/// <summary>Thrown by <c>IScanLauncher.StartAsync</c> for an invalid request (unknown workflow or network, past window...).</summary>
public sealed class ScanLaunchException(string message) : Exception(message);
