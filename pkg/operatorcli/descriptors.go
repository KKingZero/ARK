package operatorcli

import "github.com/KKingZero/ARK/pkg/taskmeta"

type commandDescriptor struct {
	Name         string
	Handler      func(*Commands, []string) error
	NeedsSession bool
	Fanout       taskmeta.FanoutMode
	Usage        string
	Help         string
}

func commandDescriptors() []commandDescriptor {
	return []commandDescriptor{
		desc("sessions", (*Commands).cmdSessions, "List active sessions"),
		descUsage("use", (*Commands).cmdUse, "use <session-id|id,id|alive|all>", "Select active session"),
		descUsage("shell", (*Commands).cmdShell, "shell <command...>", "Execute shell command"),
		descUsage("upload", (*Commands).cmdUpload, "upload <local> <remote>", "Upload file"),
		descUsage("download", (*Commands).cmdDownload, "download <remote>", "Download file"),
		desc("ps", (*Commands).cmdPS, "List processes"),
		descUsage("kill", (*Commands).cmdKill, "kill <pid>", "Kill process"),
		desc("ifconfig", (*Commands).cmdIfconfig, "List network interfaces"),
		descUsage("portscan", (*Commands).cmdPortscan, "portscan <host> <ports>", "TCP port scan"),
		descUsage("sleep", (*Commands).cmdSleep, "sleep <ms> [jitter]", "Set beacon interval"),
		descUsage("generate", (*Commands).cmdGenerate, "generate [opts]", "Build implant"),
		descUsage("register-secret", (*Commands).cmdRegisterSecret, "register-secret <implant_id> <secret_hex> [build_id]", "Register PSK for manual implant builds"),
		desc("tasks", (*Commands).cmdTasks, "List session tasks"),
		descUsage("result", (*Commands).cmdResult, "result <task-id>", "Get task result"),
		desc("loot", (*Commands).cmdLoot, "List loot"),
		desc("events", (*Commands).cmdEvents, "Stream events"),
		desc("listeners", (*Commands).cmdListeners, "List listeners"),
		descUsage("approve", (*Commands).cmdApprove, "approve <id>", "Approve operation"),
		descUsage("deny", (*Commands).cmdDeny, "deny <id> [reason]", "Deny operation"),
		desc("pending", (*Commands).cmdPending, "List pending approvals"),
		desc("screenshot", (*Commands).cmdScreenshot, "Take screenshot"),
		descUsage("keylog", (*Commands).cmdKeylog, "keylog <start|stop|dump>", "Keylogger control"),
		desc("inject", (*Commands).cmdInject, "Queue binary injection payload"),
		descUsage("ldap-enum", (*Commands).cmdLDAPEnum, "ldap-enum <type> --domain D --dc DC [--user U] [--pass P] [--hash H]", "LDAP AD enumeration"),
		descUsage("kerberos", (*Commands).cmdKerberos, "kerberos <skew|with-skew> --dc H ...", "Kerberos clock preflight helpers"),
		descUsage("kerberoast", (*Commands).cmdKerberoast, "kerberoast --domain D --dc DC --user U --pass P", "Kerberoast SPNs"),
		descUsage("asreproast", (*Commands).cmdASREPRoast, "asreproast --domain D --dc DC", "AS-REP roast users"),
		descUsage("creds-dump", (*Commands).cmdCredsDump, "creds-dump <lsass|sam|browser|ssh_keys|history|env|files>", "Dump credentials"),
		descUsage("lateral", (*Commands).cmdLateral, "lateral <wmi|winrm|psexec> <target> <command> [--user U] [--pass P] [--hash H]", "Lateral movement"),
		descUsage("smb", (*Commands).cmdSMB, "smb <list_shares|list_dir|download> --host H [--share S] [--path P] [--anon]", "Remote SMB client"),
		descUsage("persist", (*Commands).cmdPersist, "persist <schtask|registry|service|cron|systemd_user|bashrc> [--path P] [--name N]", "Install persistence"),
		descUsage("privesc", (*Commands).cmdPrivesc, "privesc <token|uac_fodhelper|uac_eventvwr|enum> [--pid N] [--command C]", "Privilege escalation"),
		descUsage("cloud", (*Commands).cmdCloud, "cloud <aws|azure|all> [env|creds|cli|imds|all|sts-caller|me]", "Cloud credential harvest"),
		descUsage("mqtt", (*Commands).cmdMQTT, "mqtt <sub|pub|healthcheck-hijack> ...", "Pre-implant MQTT helpers"),
		descUsage("relay", (*Commands).cmdRelay, "relay http <start|sessions|get|status>", "Pre-implant HTTP NTLM relay"),
		descUsage("ldap", (*Commands).cmdHostLDAP, "ldap <bind|enum|dangling> ...", "Host-side LDAP helpers"),
		descUsage("ad", (*Commands).cmdHostAD, "ad <password|add-computer|shadow|dcsync|...> ...", "Host-side AD helpers"),
		descUsage("host-smb", (*Commands).cmdHostSMB, "host-smb <shares|ls|get> ...", "Host-side SMB helpers"),
		descUsage("inbound", (*Commands).cmdInbound, "inbound [status|env|drop|through|close|tunnel]", "C2 reachability / SOCKS env"),
		desc("adcs", (*Commands).cmdADCS, "Host-side ADCS helpers"),
		descUsage("socks", (*Commands).cmdSocks, "socks <start|stop> [--port 1080]", "Reverse SOCKS over beacon"),
		desc("approve-all", (*Commands).cmdApproveAll, "Approve all pending operations"),
		descUsage("replay-clear", (*Commands).cmdReplayClear, "replay-clear <implant_id>", "Clear replay cache for implant"),
		{Name: "clear-replay", Handler: (*Commands).cmdReplayClear, Usage: "clear-replay <implant_id>", Help: "Clear replay cache for implant"},
		desc("exit", (*Commands).cmdExit, "Exit operator CLI"),
		desc("help", (*Commands).cmdHelp, "Show this help"),
	}
}

func desc(name string, handler func(*Commands, []string) error, help string) commandDescriptor {
	return descUsage(name, handler, name, help)
}

func descUsage(name string, handler func(*Commands, []string) error, usage string, help string) commandDescriptor {
	d := commandDescriptor{Name: name, Handler: handler, Fanout: taskmeta.FanoutNone, Help: help}
	d.Usage = usage
	if meta, ok := taskmeta.ByCommand(name); ok {
		d.NeedsSession = meta.NeedsSession
		d.Fanout = meta.Fanout
	}
	return d
}

func commandDescriptorByName(name string) (commandDescriptor, bool) {
	for _, d := range commandDescriptors() {
		if d.Name == name {
			return d, true
		}
	}
	return commandDescriptor{}, false
}
