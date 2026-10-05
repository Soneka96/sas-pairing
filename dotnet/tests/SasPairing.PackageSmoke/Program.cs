using System.Reflection;
using SasPairing;

// P9-D-006 package-consumer smoke: the public API of the PACKED SasPairing assembly against the separately staged
// native library, loaded from the explicit absolute path given as the only argument (Windows x64).
if (args.Length != 1 || !Path.IsPathFullyQualified(args[0]))
{
    Console.Error.WriteLine("usage: SasPairing.PackageSmoke <absolute path of the staged sas_pairing_core.dll>");
    return 2;
}

Assembly package = typeof(SasPairingRuntime).Assembly;
Console.WriteLine($"package assembly: {package.Location}");
Console.WriteLine($"package version: {package.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion}");

SasPairingRuntime runtime = SasPairingRuntime.Create(args[0]);
Console.WriteLine("runtime: created");

// A fresh binary scope, so that no other authority of this Windows account collides with it.
SasPairingAuthority authority = runtime.RegisterAuthority(Guid.NewGuid().ToByteArray());
SasPairingAuthorityStatus status = authority.GetStatus();
Console.WriteLine($"authority: {status.State} {status.RemainingOpportunities}");
if (status.State != SasPairingAuthorityState.Ready || status.RemainingOpportunities != 10)
{
    Console.Error.WriteLine("unexpected authority status");
    return 1;
}

SasPairingHost host = authority.CreateHost();
Console.WriteLine($"host: created ({host.NetworkState})");

host.Dispose();
authority.Dispose();
runtime.Dispose();
if (!host.IsDisposed || !authority.IsDisposed || !runtime.IsDisposed)
{
    Console.Error.WriteLine("deterministic disposal failed");
    return 1;
}

Console.WriteLine("disposed: host, authority, runtime");
Console.WriteLine("package consumer smoke: OK");
return 0;
