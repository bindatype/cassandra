package agent

const (
	operationCapabilitiesDescribe = "capabilities.describe"
	operationHostInfo             = "host.info"
	operationFilesystemList       = "filesystem.list"
	operationFilesystemStat       = "filesystem.stat"
	operationFilesystemRead       = "filesystem.read"
	operationFilesystemTail       = "filesystem.tail"
	operationProcessList          = "process.list"
	operationHostUptime           = "host.uptime"
	operationHostDiskFree         = "host.diskfree"
	operationHostNetwork          = "host.network"
)

var operationCatalog = []OperationCapability{
	{Name: operationCapabilitiesDescribe, Description: "Describe enabled operations and limits."},
	{Name: operationHostInfo, Description: "Return policy-selected host and runtime information."},
	{Name: operationFilesystemList, Description: "List entries in an allowlisted directory.", TargetKinds: []string{"directory"}},
	{Name: operationFilesystemStat, Description: "Return metadata for an allowlisted path.", TargetKinds: []string{"file", "directory"}},
	{Name: operationFilesystemRead, Description: "Read a bounded byte range from an allowlisted file.", TargetKinds: []string{"file"}},
	{Name: operationFilesystemTail, Description: "Return the trailing bytes from an allowlisted file.", TargetKinds: []string{"file"}},
	{Name: operationProcessList, Description: "List bounded process metadata without command-line arguments."},
	{Name: operationHostUptime, Description: "Report load average and uptime as uptime(1) states them."},
	{Name: operationHostDiskFree, Description: "Report filesystem capacity and inode use together, because either can exhaust alone."},
	{Name: operationHostNetwork, Description: "Report interface addresses and the routing table together."},
}

var knownOperations = func() map[string]struct{} {
	known := make(map[string]struct{}, len(operationCatalog))
	for _, capability := range operationCatalog {
		known[capability.Name] = struct{}{}
	}
	return known
}()

func defaultEnabledOperations() []string {
	return []string{
		operationCapabilitiesDescribe,
		operationHostInfo,
		operationFilesystemList,
		operationFilesystemStat,
		operationFilesystemRead,
		operationFilesystemTail,
		operationHostUptime,
		operationHostDiskFree,
		operationHostNetwork,
	}
}

const (
	hostInfoHostname      = "hostname"
	hostInfoOS            = "os"
	hostInfoArch          = "arch"
	hostInfoCPUs          = "cpus"
	hostInfoUptimeSeconds = "uptime_seconds"
	hostInfoKernelVersion = "kernel_version"
)

var knownHostInfoFields = map[string]struct{}{
	hostInfoHostname:      {},
	hostInfoOS:            {},
	hostInfoArch:          {},
	hostInfoCPUs:          {},
	hostInfoUptimeSeconds: {},
	hostInfoKernelVersion: {},
}

func defaultHostInfoFields() []string {
	return []string{
		hostInfoHostname,
		hostInfoOS,
		hostInfoArch,
		hostInfoCPUs,
		hostInfoUptimeSeconds,
		hostInfoKernelVersion,
	}
}
