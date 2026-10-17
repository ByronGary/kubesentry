package investigate

import (
	"regexp"
	"strings"
)

// ReadOnlyCommand reports whether a suggested command is one of the
// read-only forms a report may suggest: kubectl get, describe, logs, top,
// events, explain, auth can-i, rollout history, rollout status,
// api-resources, version; cmctl status; helm status, history, get; and aws
// <service> describe-*, get-*, list-*, lookup-*.
//
// The model writes these from untrusted cluster data, and a person runs
// them with their own credentials, so the verb is not enough: a flag can
// send the request (and its token or signature) elsewhere (kubectl
// --server, helm --kube-apiserver, aws --endpoint-url), read a local file
// into the request (aws file://), or write one (aws s3api get-object's
// outfile). The command is therefore split as a POSIX shell would split it
// and every argument checked: kubectl, helm and cmctl take only flags known
// to change what is shown, and aws refuses endpoint, CA and input-file
// options, URLs, positional arguments and object downloads. Anything a shell
// would expand or chain (; | & $ ` < > \, globs, braces, ~, !, control
// characters) is refused outright.
func ReadOnlyCommand(cmd string) bool {
	args, ok := shellSplit(cmd)
	if !ok || len(args) < 2 {
		return false
	}
	switch args[0] {
	case "kubectl":
		return kubectlReadOnly(args[1:])
	case "helm":
		return helmReadOnly(args[1:])
	case "cmctl":
		return len(args) >= 2 && args[1] == "status" && flagsOK(args[2:], cmctlFlags)
	case "aws":
		return awsReadOnly(args[1:])
	}
	return false
}

// shellSplit splits cmd into the words a POSIX shell would pass, accepting
// only what needs no expansion: plain words, and single- or double-quoted
// parts. It refuses operators and expansions anywhere (even inside quotes,
// to keep the rule simple), control characters, and unbalanced quotes;
// globs, braces, "~" and "!" only outside quotes.
func shellSplit(cmd string) ([]string, bool) {
	if strings.ContainsAny(cmd, ";|&$`<>\\") {
		return nil, false
	}
	var (
		args  []string
		cur   strings.Builder
		inArg bool
		quote rune
	)
	for _, r := range cmd {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0xa0) || r == 0x200b || r == 0xfeff {
			return nil, false // control characters, NBSP and zero-width tricks
		}
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inArg = r, true
		case r == ' ':
			if inArg {
				args, inArg = append(args, cur.String()), false
				cur.Reset()
			}
		case strings.ContainsRune("*?[]{}~!#", r):
			return nil, false // globbing, brace expansion, home, history, comments
		default:
			cur.WriteRune(r)
			inArg = true
		}
	}
	if quote != 0 {
		return nil, false
	}
	if inArg {
		args = append(args, cur.String())
	}
	return args, true
}

// flagSpec lists the flags a tool may take: true takes a value.
type flagSpec map[string]bool

// flagsOK checks args against spec: positional words are names; flags must
// be listed, as --long, --long=value, -s, -s value or -svalue (a value
// flag's shorthand with its value attached). A value never starts with "-",
// so a refused flag cannot hide as the value of an allowed one.
func flagsOK(args []string, spec flagSpec) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "" || a[0] != '-' {
			continue // a resource, release or certificate name
		}
		name, val, hasVal := strings.Cut(a, "=")
		if !strings.HasPrefix(a, "--") && len(name) > 2 {
			// -oyaml, -nshop: a value shorthand with its value attached.
			name, val, hasVal = a[:2], a[2:], true
		}
		takes, known := spec[name]
		if !known {
			return false
		}
		switch {
		case hasVal && val == "":
			return false
		case hasVal && !takes:
			if val != "true" && val != "false" {
				return false
			}
		case !hasVal && takes:
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return false
			}
			i++
		}
	}
	return true
}

var (
	kubectlCommon = flagSpec{
		"-n": true, "--namespace": true, "-A": false, "--all-namespaces": false,
		"-l": true, "--selector": true, "--field-selector": true,
		"-o": true, "--output": true, "--context": true,
		"--request-timeout": true,
	}
	kubectlVerbs = map[string]flagSpec{
		"get": {"-L": true, "--label-columns": true, "--show-labels": false, "--no-headers": false, "--show-kind": false,
			"--sort-by": true, "--ignore-not-found": false, "-w": false, "--watch": false, "--chunk-size": true,
			"--subresource": true},
		"describe": {"--show-events": false, "--chunk-size": true},
		"logs": {"-c": true, "--container": true, "--all-containers": false, "-p": false, "--previous": false,
			"--tail": true, "--since": true, "--since-time": true, "--timestamps": false, "--prefix": false,
			"--limit-bytes": true, "--max-log-requests": true, "--ignore-errors": false},
		"top":           {"--containers": false, "--sort-by": true, "--no-headers": false, "--sum": false},
		"events":        {"--for": true, "--types": true, "-w": false, "--watch": false, "--no-headers": false},
		"explain":       {"--recursive": false, "--api-version": true},
		"api-resources": {"--namespaced": false, "--api-group": true, "--verbs": true, "--sort-by": true, "--no-headers": false},
		"version":       {"--client": false},
	}
	kubectlCanI    = flagSpec{"--list": false, "--as": true, "--as-group": true, "--subresource": true, "--no-headers": false}
	kubectlRollout = flagSpec{"--revision": true, "--timeout": true, "-w": false, "--watch": false}

	helmFlags = flagSpec{
		"-n": true, "--namespace": true, "--kube-context": true, "--revision": true,
		"-o": true, "--output": true, "--max": true, "-a": false, "--all": false,
		"--show-desc": false, "--show-resources": false, "--template": true,
	}
	cmctlFlags = flagSpec{"-n": true, "--namespace": true, "--context": true}
)

func merge(a, b flagSpec) flagSpec {
	m := make(flagSpec, len(a)+len(b))
	for k, v := range a {
		m[k] = v
	}
	for k, v := range b {
		m[k] = v
	}
	return m
}

func kubectlReadOnly(args []string) bool {
	verb := args[0]
	switch verb {
	case "auth":
		return len(args) >= 2 && args[1] == "can-i" && flagsOK(args[2:], merge(kubectlCommon, kubectlCanI))
	case "rollout":
		return len(args) >= 2 && (args[1] == "history" || args[1] == "status") && flagsOK(args[2:], merge(kubectlCommon, kubectlRollout))
	}
	spec, ok := kubectlVerbs[verb]
	return ok && flagsOK(args[1:], merge(kubectlCommon, spec))
}

func helmReadOnly(args []string) bool {
	switch args[0] {
	case "status", "history", "get":
		return flagsOK(args[1:], helmFlags)
	}
	return false
}

var (
	awsService = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	awsOp      = regexp.MustCompile(`^(describe|get|list|lookup)-[a-z0-9-]+$`)
	// Options that point the request at another endpoint, trust another CA,
	// or read the request from a file or URL.
	awsDenied = map[string]bool{
		"--endpoint-url": true, "--ca-bundle": true, "--no-verify-ssl": true,
		"--cli-input-json": true, "--cli-input-yaml": true,
	}
)

// awsReadOnly checks aws <service> <op> [--param value | --flag]... The
// operation must read (describe-, get-, list-, lookup-) and not download an
// object to a local file (get-object and the other operations with an
// outfile argument take a bare positional, which is refused too).
func awsReadOnly(args []string) bool {
	if len(args) < 2 || !awsService.MatchString(args[0]) || !awsOp.MatchString(args[1]) {
		return false
	}
	if strings.Contains(args[1], "object") || args[1] == "get-job-output" || args[1] == "get-media" ||
		args[1] == "get-snapshot-block" || args[1] == "get-clip" {
		return false
	}
	prevFlag := false // the previous word was a --param without "=", so this word may be its value
	for _, a := range args[2:] {
		if strings.Contains(a, "://") {
			return false // file://, fileb://, http(s):// parameter values
		}
		if strings.HasPrefix(a, "--") {
			name, _, hasVal := strings.Cut(a, "=")
			if awsDenied[name] {
				return false
			}
			prevFlag = !hasVal
			continue
		}
		if strings.HasPrefix(a, "-") || !prevFlag {
			return false // a short flag, or a positional (an outfile)
		}
		prevFlag = false
	}
	return true
}
