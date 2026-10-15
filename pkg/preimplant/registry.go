package preimplant

import (
	"fmt"
	"sort"
	"strings"
)

type HostCommand struct {
	Name string
	Run  func([]string) error
}

var hostCommands = map[string]HostCommand{
	"mqtt":     {Name: "mqtt", Run: RunMQTT},
	"relay":    {Name: "relay", Run: RunRelay},
	"ldap":     {Name: "ldap", Run: RunLDAP},
	"smb":      {Name: "smb", Run: RunSMB},
	"ad":       {Name: "ad", Run: RunAD},
	"kerberos": {Name: "kerberos", Run: RunKerberos},
	"rbcd":     {Name: "rbcd", Run: RunRBCD},
	"inbound":  {Name: "inbound", Run: RunInbound},
	"adcs":     {Name: "adcs", Run: RunADCS},
	"winrm":    {Name: "winrm", Run: RunWinRM},
	"psexec":   {Name: "psexec", Run: RunPsExec},
	"http":     {Name: "http", Run: RunHTTP},
	"dns":      {Name: "dns", Run: RunDNS},
	"mssql":    {Name: "mssql", Run: RunMSSQL},
}

func RunHostCommand(name string, args []string) error {
	cmd, ok := hostCommands[strings.ToLower(name)]
	if !ok {
		return fmt.Errorf("unknown host command %q", name)
	}
	return cmd.Run(args)
}

func IsHostCommand(name string) bool {
	_, ok := hostCommands[strings.ToLower(name)]
	return ok
}

func HostCommandNames() []string {
	names := make([]string, 0, len(hostCommands))
	for name := range hostCommands {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
