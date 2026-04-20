package fastallow

import "strings"

// CLI handlers ported from Dippy's src/dippy/cli/*.py — extended set.
// Same signature/contract as cliHandler in handlers.go.
//
// Attribution: Dippy is MIT-licensed by Lily Dayton.
// https://github.com/ldayton/Dippy

// hasDangerousFlag reports whether tokens contain any flag in danger (either
// as a standalone `--flag` or as `--flag=value`). Used by multiplex-tool
// handlers to refuse invocations that can hijack execution via config-file
// or server-URL overrides — e.g. docker --config, kubectl --kubeconfig,
// helm --kube-apiserver. Each of these can point the tool at a crafted
// config whose values trigger arbitrary shell execution (exec plugins,
// credHelpers, credential_process, ProxyCommand, etc.). The AI can write
// the config file first and then reference it via the flag, so rejection
// is the safe default — the LLM layer can still approve on a case-by-case
// basis if the target path is obviously benign.
func hasDangerousFlag(tokens []string, danger map[string]struct{}) bool {
	for _, t := range tokens {
		if _, bad := danger[t]; bad {
			return true
		}
		if eq := strings.IndexByte(t, '='); eq > 0 {
			if _, bad := danger[t[:eq]]; bad {
				return true
			}
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// aws — prefix- and keyword-based safe-action matching.
// Port of src/dippy/cli/aws.py. Athena SQL analysis deliberately skipped.
// -----------------------------------------------------------------------------

var awsGlobalFlagsWithArg = map[string]struct{}{
	"--region": {}, "--profile": {}, "--output": {},
	"--endpoint-url":       {},
	"--cli-connect-timeout": {}, "--cli-read-timeout": {},
	"--ca-bundle": {}, "--color": {}, "--query": {},
}

var awsSafeActionPrefixes = []string{
	"describe-", "list-", "get-", "show-", "head-",
	"lookup-", "filter-", "validate-", "estimate-",
	"simulate-", "generate-", "download-", "detect-",
	"test-", "check-if-", "admin-get-", "admin-list-",
}

var awsSafeActionsExact = map[string]struct{}{
	"ls": {}, "wait": {}, "help": {}, "query": {}, "scan": {},
	"tail":             {},
	"receive-message":  {},
	"batch-get-item":   {},
	"transact-get-items": {},
	"batch-get-image":  {},
	"start-query":      {}, "stop-query": {},
}

var awsUnsafeExceptions = map[string]struct{}{
	"assume-role":                  {},
	"assume-role-with-saml":        {},
	"assume-role-with-web-identity": {},
	"get-secret-value":             {},
	"start-image-scan":             {},
}

var awsUnsafeActionKeywords = map[string]struct{}{
	"create": {}, "delete": {}, "remove": {}, "rm": {},
	"put": {}, "update": {}, "modify": {}, "set": {},
	"start": {}, "stop": {}, "terminate": {}, "reboot": {},
	"attach": {}, "detach": {}, "associate": {}, "disassociate": {},
	"authorize": {}, "revoke": {}, "copy": {}, "cp": {},
	"mv": {}, "sync": {}, "mb": {}, "rb": {},
	"invoke": {}, "execute": {}, "run": {},
	"enable": {}, "disable": {},
	"register": {}, "deregister": {},
	"import": {}, "export": {},
}

var awsAlwaysSafeServices = map[string]struct{}{
	"pricing": {},
}

var awsStsSafeActions = map[string]struct{}{
	"get-caller-identity":           {},
	"get-session-token":             {},
	"get-access-key-info":           {},
	"get-federation-token":          {},
	"decode-authorization-message":  {},
}

// awsSafeCommands — specific (service, action) pairs.
var awsSafeCommands = map[string]map[string]struct{}{
	"s3":    {"ls": {}},
	"s3api": {
		"list-buckets": {}, "list-objects": {}, "list-objects-v2": {},
		"head-object": {}, "head-bucket": {},
		"get-object-tagging": {}, "get-bucket-tagging": {},
		"get-bucket-location": {},
	},
	"ec2": {
		"describe-instances": {}, "describe-vpcs": {},
		"describe-subnets": {}, "describe-security-groups": {},
	},
	"iam": {
		"list-users": {}, "list-roles": {}, "list-policies": {},
		"get-user": {}, "get-role": {},
	},
	"lambda": {"list-functions": {}, "get-function": {}},
	"rds":    {"describe-db-instances": {}, "describe-db-clusters": {}},
	"ecs": {
		"list-clusters": {}, "list-services": {}, "list-tasks": {},
		"describe-clusters": {}, "describe-services": {}, "describe-tasks": {},
	},
	"cloudformation": {
		"list-stacks": {}, "describe-stacks": {},
		"describe-stack-resources": {}, "get-template": {},
	},
	"logs": {
		"describe-log-groups": {}, "describe-log-streams": {},
		"filter-log-events": {}, "get-log-events": {},
	},
	"ssm": {
		"describe-parameters":    {},
		"get-parameter":          {}, "get-parameters": {},
		"get-parameters-by-path": {},
	},
	"secretsmanager": {"list-secrets": {}, "describe-secret": {}},
	"route53": {
		"list-hosted-zones":         {},
		"list-resource-record-sets": {},
	},
	"cloudwatch": {
		"list-metrics": {}, "get-metric-statistics": {},
		"describe-alarms": {},
	},
	"sqs": {"list-queues": {}, "get-queue-attributes": {}},
	"sns": {"list-topics": {}, "list-subscriptions": {}},
	"dynamodb": {
		"list-tables": {}, "describe-table": {},
	},
	"athena": {
		"list-databases": {}, "list-data-catalogs": {}, "list-engine-versions": {},
		"list-named-queries": {}, "list-query-executions": {},
		"list-prepared-statements": {}, "list-work-groups": {},
		"list-table-metadata": {}, "list-tags-for-resource": {},
		"get-database": {}, "get-data-catalog": {}, "get-named-query": {},
		"get-prepared-statement": {}, "get-query-execution": {},
		"get-query-results": {}, "get-query-runtime-statistics": {},
		"get-table-metadata": {}, "get-work-group": {},
		"batch-get-named-query": {}, "batch-get-query-execution": {},
		"batch-get-prepared-statement": {},
	},
}

// awsFindServiceAction walks tokens past `aws`, skipping global flags and
// their values, to locate (service, action).
func awsFindServiceAction(tokens []string) (service, action string) {
	i := 1
	for i < len(tokens) {
		t := tokens[i]
		if strings.HasPrefix(t, "--") {
			if _, consumesArg := awsGlobalFlagsWithArg[t]; consumesArg {
				i += 2
				continue
			}
			if strings.Contains(t, "=") {
				i++
				continue
			}
			i++
			continue
		}
		if strings.HasPrefix(t, "-") {
			i++
			continue
		}
		if service == "" {
			service = t
			i++
			continue
		}
		action = t
		return
	}
	return
}

var awsDangerousFlags = map[string]struct{}{
	// --ca-bundle: bypasses TLS trust chain via attacker-controlled bundle.
	"--ca-bundle": {},
	// --endpoint-url: repoints the SDK at an attacker server that captures
	// the default-profile credentials the AWS CLI signs with.
	"--endpoint-url": {},
}

func awsHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	if hasDangerousFlag(tokens, awsDangerousFlags) {
		return false, ""
	}
	// --help / -h anywhere → allow.
	for _, t := range tokens {
		if t == "--help" || t == "-h" {
			return true, "aws"
		}
	}
	service, action := awsFindServiceAction(tokens)
	if service == "" {
		return false, ""
	}
	if service == "help" || action == "help" {
		return true, "aws " + service
	}
	if _, ok := awsAlwaysSafeServices[service]; ok {
		return true, "aws " + service
	}
	switch service {
	case "sts":
		if _, ok := awsStsSafeActions[action]; ok {
			return true, "aws sts " + action
		}
		return false, ""
	case "configure":
		if action == "list" || action == "list-profiles" || action == "get" {
			return true, "aws configure " + action
		}
		return false, ""
	}
	// ssm with --with-decryption → ask.
	if service == "ssm" {
		for _, t := range tokens {
			if t == "--with-decryption" {
				return false, ""
			}
		}
	}
	// Athena start-query-execution: skip SQL analysis, fall through.
	if service == "athena" && action == "start-query-execution" {
		return false, ""
	}
	// Specific safe (service, action) pair.
	if acts, ok := awsSafeCommands[service]; ok {
		if _, safe := acts[action]; safe {
			return true, "aws " + service + " " + action
		}
	}
	if action == "" {
		return false, ""
	}
	// Exceptions (safe-looking but actually unsafe).
	if _, bad := awsUnsafeExceptions[action]; bad {
		return false, ""
	}
	// Exact safe actions.
	if _, ok := awsSafeActionsExact[action]; ok {
		return true, "aws " + service + " " + action
	}
	// Safe prefixes.
	for _, p := range awsSafeActionPrefixes {
		if strings.HasPrefix(action, p) {
			return true, "aws " + service + " " + action
		}
	}
	// Unsafe keyword anywhere in action name → ask.
	for kw := range awsUnsafeActionKeywords {
		if strings.Contains(action, kw) {
			return false, ""
		}
	}
	// Default: ask.
	return false, ""
}

// -----------------------------------------------------------------------------
// gcloud / gsutil. Port of src/dippy/cli/gcloud.py.
// -----------------------------------------------------------------------------

var gcloudFlagsWithArg = map[string]struct{}{
	"--project": {}, "--region": {}, "--zone": {}, "--format": {},
	"--filter": {}, "--cluster": {}, "--location": {}, "--instance": {},
	"--secret": {}, "--service": {}, "--keyring": {},
	"--member": {}, "--role": {},
}

var gcloudSafeActionKeywords = map[string]struct{}{
	"describe": {}, "list": {}, "get": {}, "show": {},
	"info": {}, "status": {}, "version": {},
	"get-credentials":        {},
	"list-tags":              {},
	"list-grantable-roles":   {},
	"read":                   {},
	"configurations":         {},
}

var gcloudSafeActionPrefixes = []string{"list-", "describe-", "get-"}

var gcloudUnsafeActionKeywords = map[string]struct{}{
	"create": {}, "delete": {}, "remove": {}, "update": {}, "set": {},
	"add": {}, "patch": {}, "start": {}, "stop": {}, "restart": {},
	"reset": {}, "deploy": {}, "undelete": {}, "enable": {}, "disable": {},
	"import": {}, "export": {}, "ssh": {}, "scp": {},
	"login": {}, "activate": {}, "revoke": {},
	"configure-docker":   {},
	"print-access-token": {},
}

var gcloudUnsafeActionPatterns = []string{
	"add-iam-policy-binding",
	"remove-iam-policy-binding",
	"set-iam-policy",
}

var gcloudGsutilSafeActions = map[string]struct{}{
	"ls": {}, "cat": {}, "stat": {}, "du": {},
	"hash": {}, "version": {}, "help": {},
}

func gcloudLooksLikeValue(tok string) bool {
	if strings.HasPrefix(tok, "gs://") || strings.HasPrefix(tok, "gcr.io/") ||
		strings.HasPrefix(tok, "//") || strings.Contains(tok, "@") {
		return true
	}
	if tok != "" && tok[0] >= '0' && tok[0] <= '9' {
		allDigits := true
		for _, c := range tok {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return true
		}
	}
	if strings.HasPrefix(tok, "'") {
		return true
	}
	return false
}

func gcloudExtractParts(tokens []string) []string {
	var parts []string
	i := 0
	for i < len(tokens) && len(parts) < 6 {
		t := tokens[i]
		if strings.HasPrefix(t, "-") {
			if _, consumes := gcloudFlagsWithArg[t]; consumes && i+1 < len(tokens) {
				i += 2
				continue
			}
			if strings.Contains(t, "=") {
				i++
				continue
			}
			i++
			continue
		}
		if gcloudLooksLikeValue(t) {
			i++
			continue
		}
		parts = append(parts, t)
		i++
	}
	return parts
}

func gsutilHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	var action string
	for _, t := range tokens[1:] {
		if !strings.HasPrefix(t, "-") {
			action = t
			break
		}
	}
	if action == "" {
		return false, ""
	}
	if _, ok := gcloudGsutilSafeActions[action]; ok {
		return true, "gsutil " + action
	}
	return false, ""
}

func gcloudHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	parts := gcloudExtractParts(tokens[1:])
	if len(parts) == 0 {
		return false, ""
	}
	for _, t := range tokens {
		if t == "--help" || t == "-h" {
			return true, "gcloud " + parts[0]
		}
	}
	for _, p := range parts {
		if p == "help" {
			return true, "gcloud " + parts[0]
		}
	}
	switch parts[0] {
	case "version", "info", "topic":
		return true, "gcloud " + parts[0]
	case "config":
		if len(parts) > 1 {
			if parts[1] == "set" {
				return false, ""
			}
			if parts[1] == "configurations" && len(parts) > 2 {
				switch parts[2] {
				case "create", "activate", "delete":
					return false, ""
				}
				return true, "gcloud config configurations " + parts[2]
			}
			switch parts[1] {
			case "list", "get", "configurations":
				return true, "gcloud config " + parts[1]
			}
		}
		return true, "gcloud config"
	case "auth":
		if len(parts) > 1 && parts[1] == "list" {
			return true, "gcloud auth list"
		}
		return false, ""
	case "projects":
		if len(parts) > 1 {
			switch parts[1] {
			case "list", "describe", "get-ancestors", "get-iam-policy":
				return true, "gcloud projects " + parts[1]
			case "create", "delete", "undelete", "update":
				return false, ""
			}
			if strings.Contains(parts[1], "iam-policy-binding") ||
				strings.Contains(parts[1], "iam-policy") {
				return false, ""
			}
			return false, ""
		}
		return true, "gcloud projects"
	}

	// Skip beta/alpha prefix.
	var actionParts []string
	for _, p := range parts {
		if p != "beta" && p != "alpha" {
			actionParts = append(actionParts, p)
		}
	}

	// Unsafe patterns take precedence.
	for _, p := range actionParts {
		for _, pat := range gcloudUnsafeActionPatterns {
			if strings.Contains(p, pat) {
				return false, ""
			}
		}
	}
	for _, p := range actionParts {
		if _, bad := gcloudUnsafeActionKeywords[p]; bad {
			return false, ""
		}
	}
	for _, p := range actionParts {
		if _, ok := gcloudSafeActionKeywords[p]; ok {
			return true, "gcloud " + parts[0]
		}
		for _, pref := range gcloudSafeActionPrefixes {
			if strings.HasPrefix(p, pref) {
				return true, "gcloud " + parts[0]
			}
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// azure (az CLI). Port of src/dippy/cli/azure.py.
// -----------------------------------------------------------------------------

var azFlagsWithArg = map[string]struct{}{
	"--resource-group": {}, "-g": {},
	"--subscription": {}, "-s": {},
	"--name": {}, "-n": {},
	"--output": {}, "-o": {},
	"--query":    {},
	"--location": {}, "-l": {},
	"--ids": {}, "--id": {},
	"--workspace-name": {}, "--workspace": {},
	"--vault-name": {}, "--vault": {},
	"--server": {}, "--server-name": {},
	"--database": {}, "--database-name": {},
	"--namespace-name": {}, "--namespace": {},
	"--container-name": {}, "--container": {},
	"--account-name": {}, "--account": {},
	"--storage-account": {},
	"--registry":        {}, "--registry-name": {},
	"--repository":   {},
	"--project":      {},
	"--organization": {}, "--org": {},
	"--pipeline-id": {}, "--build-id": {}, "--release-id": {},
	"--pool-id":  {},
	"--group-id": {}, "--team": {},
	"--assignee": {}, "--scope": {},
	"--analytics-query": {}, "--wiql": {},
	"--publisher": {}, "--offer": {}, "--sku": {}, "--urn": {},
	"--start-time":  {},
	"--end-time":    {},
	"--resource":    {},
	"--resource-type": {},
	"--resource-id": {},
}

var azSafeActionKeywords = map[string]struct{}{
	"show": {}, "list": {}, "get": {}, "exists": {}, "query": {},
	"list-sizes": {}, "list-skus": {}, "list-offers": {},
	"list-publishers": {}, "list-member": {}, "list-definitions": {},
	"show-tags": {}, "summarize": {}, "logs": {}, "check-health": {},
	"url":      {},
	"download": {}, "download-batch": {},
	"tail": {},
}

var azSafeActionPrefixes = []string{"list-", "show-", "get-"}

var azUnsafeExceptions = map[string]struct{}{
	"get-credentials": {},
}

var azUnsafeActionKeywords = map[string]struct{}{
	"create": {}, "delete": {}, "update": {}, "set": {},
	"start": {}, "stop": {}, "restart": {},
	"add": {}, "remove": {}, "clear": {},
	"run": {}, "invoke": {}, "execute": {},
}

var azSafeGroups = map[string]struct{}{
	"version": {}, "find": {},
}

var azUnsafeGroups = map[string]struct{}{
	"login": {}, "logout": {}, "configure": {},
}

var azAccountSafeCommands = map[string]struct{}{
	"show": {}, "list": {}, "get-access-token": {},
}

var azAccountUnsafeCommands = map[string]struct{}{
	"set": {}, "clear": {},
}

func azLooksLikeValue(tok string) bool {
	if len(tok) == 36 && strings.Count(tok, "-") == 4 {
		return true
	}
	if tok != "" && tok[0] >= '0' && tok[0] <= '9' {
		allDigits := true
		for _, c := range tok {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return true
		}
	}
	if strings.HasPrefix(tok, "/subscriptions/") {
		return true
	}
	return false
}

func azExtractParts(tokens []string) []string {
	var parts []string
	i := 0
	for i < len(tokens) && len(parts) < 5 {
		t := tokens[i]
		if strings.HasPrefix(t, "-") {
			if _, consumes := azFlagsWithArg[t]; consumes && i+1 < len(tokens) {
				i += 2
				continue
			}
			if strings.Contains(t, "=") {
				i++
				continue
			}
			i++
			continue
		}
		if strings.Contains(t, "/") || strings.Contains(t, ".") || strings.Contains(t, "@") {
			i++
			continue
		}
		if azLooksLikeValue(t) {
			i++
			continue
		}
		parts = append(parts, t)
		i++
	}
	return parts
}

func azHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	parts := azExtractParts(tokens[1:])
	if len(parts) == 0 {
		return false, ""
	}
	for _, t := range tokens {
		if t == "--help" || t == "-h" {
			return true, "az " + parts[0]
		}
	}
	for _, p := range parts {
		if p == "help" {
			return true, "az " + parts[0]
		}
	}
	if _, bad := azUnsafeGroups[parts[0]]; bad {
		return false, ""
	}
	if _, ok := azSafeGroups[parts[0]]; ok {
		return true, "az " + parts[0]
	}
	if parts[0] == "account" {
		if len(parts) > 1 {
			if _, ok := azAccountSafeCommands[parts[1]]; ok {
				return true, "az account " + parts[1]
			}
			if _, bad := azAccountUnsafeCommands[parts[1]]; bad {
				return false, ""
			}
		}
		return true, "az account"
	}
	if parts[0] == "devops" && len(parts) > 1 && parts[1] == "configure" {
		for _, t := range tokens {
			if t == "--list" {
				return true, "az devops configure"
			}
		}
		return false, ""
	}
	if parts[0] == "bicep" && len(parts) > 1 {
		if parts[1] == "version" || parts[1] == "list-versions" {
			return true, "az bicep " + parts[1]
		}
	}
	for _, p := range parts {
		if _, bad := azUnsafeActionKeywords[p]; bad {
			return false, ""
		}
		if _, bad := azUnsafeExceptions[p]; bad {
			return false, ""
		}
		if strings.HasPrefix(p, "set-") {
			return false, ""
		}
	}
	for _, p := range parts {
		if _, ok := azSafeActionKeywords[p]; ok {
			return true, "az " + parts[0]
		}
		for _, pref := range azSafeActionPrefixes {
			if strings.HasPrefix(p, pref) {
				return true, "az " + parts[0]
			}
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// docker / docker-compose / podman / podman-compose.
// Port of src/dippy/cli/docker.py.
// exec delegates to inner command via analyzeInnerTokens.
// -----------------------------------------------------------------------------

var dockerGlobalFlagsWithArg = map[string]struct{}{
	"-H": {}, "--host": {},
	"-c": {}, "--context": {},
	"-l": {}, "--log-level": {},
	"--config":    {},
	"--tlscacert": {},
	"--tlscert":   {}, "--tlskey": {},
}

var dockerExecFlagsWithArg = map[string]struct{}{
	"-e": {}, "--env": {},
	"-w": {}, "--workdir": {},
	"-u": {}, "--user": {},
	"--env-file": {},
}

var dockerSafeActions = map[string]struct{}{
	"version": {}, "help": {}, "info": {}, "ps": {}, "images": {},
	"image": {}, "inspect": {}, "logs": {}, "stats": {}, "top": {},
	"port": {}, "diff": {}, "history": {}, "search": {}, "events": {},
	"system": {}, "network": {}, "volume": {}, "config": {},
	"context": {}, "export": {}, "save": {},
}

var dockerSafeSubcommands = map[string]map[string]struct{}{
	"image":     {"ls": {}, "list": {}, "inspect": {}, "history": {}, "save": {}},
	"container": {"ls": {}, "list": {}, "inspect": {}, "logs": {}, "stats": {}, "top": {}, "port": {}, "diff": {}, "export": {}},
	"network":   {"ls": {}, "list": {}, "inspect": {}},
	"volume":    {"ls": {}, "list": {}, "inspect": {}},
	"system":    {"df": {}, "info": {}, "events": {}},
	"context":   {"ls": {}, "list": {}, "inspect": {}, "show": {}},
	"config":    {"ls": {}, "inspect": {}},
	"secret":    {"ls": {}, "inspect": {}},
	"service":   {"ls": {}, "list": {}, "inspect": {}, "logs": {}, "ps": {}},
	"stack":     {"ls": {}, "ps": {}, "services": {}},
	"node":      {"ls": {}, "inspect": {}, "ps": {}},
	"compose":   {"ps": {}, "logs": {}, "config": {}, "images": {}, "ls": {}, "top": {}, "version": {}, "port": {}, "events": {}},
	"plugin":    {"ls": {}, "list": {}, "inspect": {}},
	"buildx":    {"ls": {}, "inspect": {}, "du": {}, "version": {}},
	"manifest":  {"inspect": {}},
	"trust":     {"inspect": {}},
}

var dockerUnsafeSubcommands = map[string]map[string]struct{}{
	"image":     {"rm": {}, "prune": {}, "build": {}, "push": {}, "pull": {}, "tag": {}, "import": {}, "load": {}},
	"container": {"rm": {}, "prune": {}, "create": {}, "start": {}, "stop": {}, "restart": {}, "kill": {}, "exec": {}},
	"network":   {"create": {}, "rm": {}, "prune": {}, "connect": {}, "disconnect": {}},
	"volume":    {"create": {}, "rm": {}, "prune": {}},
	"system":    {"prune": {}},
	"context":   {"create": {}, "update": {}, "use": {}, "rm": {}, "import": {}},
	"compose":   {"up": {}, "down": {}, "start": {}, "stop": {}, "restart": {}, "rm": {}, "pull": {}, "build": {}, "exec": {}, "run": {}},
	"config":    {"create": {}, "rm": {}},
	"secret":    {"create": {}, "rm": {}},
	"service":   {"create": {}, "rm": {}, "scale": {}, "update": {}, "rollback": {}},
	"stack":     {"deploy": {}, "rm": {}},
	"node":      {"update": {}, "rm": {}, "promote": {}, "demote": {}},
	"plugin":    {"install": {}, "enable": {}, "disable": {}, "rm": {}, "upgrade": {}, "create": {}, "push": {}},
	"buildx":    {"build": {}, "bake": {}, "create": {}, "rm": {}, "use": {}, "prune": {}},
	"manifest":  {"create": {}, "push": {}, "annotate": {}, "rm": {}},
	"trust":     {"sign": {}, "revoke": {}},
	"swarm":     {"init": {}, "join": {}, "join-token": {}, "leave": {}, "update": {}, "ca": {}, "unlock": {}, "unlock-key": {}},
}

var dockerComposeSafeSubs = map[string]struct{}{
	"ps": {}, "logs": {}, "config": {}, "images": {}, "ls": {},
	"top": {}, "version": {}, "port": {}, "events": {},
}

var dockerComposeFlagsWithArg = map[string]struct{}{
	"-f": {}, "--file": {},
	"-p": {}, "--project-name": {},
	"--project-directory": {},
	"--env-file":          {},
	"--profile":           {},
	"--ansi":              {},
}

func dockerFindActionIdx(tokens []string) int {
	i := 1
	for i < len(tokens) {
		t := tokens[i]
		if strings.HasPrefix(t, "-") {
			if _, ok := dockerGlobalFlagsWithArg[t]; ok && i+1 < len(tokens) {
				i += 2
				continue
			}
			if strings.Contains(t, "=") {
				i++
				continue
			}
			i++
			continue
		}
		return i
	}
	return len(tokens)
}

func dockerFirstNonFlag(rest []string) string {
	for _, t := range rest {
		if !strings.HasPrefix(t, "-") {
			return t
		}
	}
	return ""
}

func dockerHasOutputFlag(rest []string) bool {
	for _, t := range rest {
		if t == "-o" || t == "--output" {
			return true
		}
		if strings.HasPrefix(t, "-o") && len(t) > 2 && !strings.HasPrefix(t, "-o=") {
			return true
		}
		if strings.HasPrefix(t, "--output=") {
			return true
		}
	}
	return false
}

func dockerExtractExecInner(rest []string) []string {
	i := 0
	// Skip flags and the container name.
	for i < len(rest) {
		t := rest[i]
		if t == "--" {
			return rest[i+1:]
		}
		if _, ok := dockerExecFlagsWithArg[t]; ok {
			i += 2
			continue
		}
		if strings.HasPrefix(t, "-") {
			if strings.Contains(t, "=") {
				i++
				continue
			}
			i++
			continue
		}
		// First non-flag is container name, inner command starts after.
		i++
		break
	}
	if i >= len(rest) {
		return nil
	}
	return rest[i:]
}

func dockerCheckCompose(tokens []string, startIdx int) bool {
	var i int
	if tokens[0] == "docker-compose" || tokens[0] == "podman-compose" {
		i = 1
	} else if startIdx < len(tokens) && tokens[startIdx] == "compose" {
		i = startIdx + 1
	} else {
		i = startIdx
	}
	for i < len(tokens) {
		t := tokens[i]
		if strings.HasPrefix(t, "-") {
			if _, ok := dockerComposeFlagsWithArg[t]; ok && i+1 < len(tokens) {
				i += 2
				continue
			}
			if strings.Contains(t, "=") {
				i++
				continue
			}
			i++
			continue
		}
		if _, ok := dockerComposeSafeSubs[t]; ok {
			return true
		}
		return false
	}
	return false
}

var dockerDangerousFlags = map[string]struct{}{
	// --config <dir>: points at a config dir whose config.json credHelpers
	// are invoked as `docker-credential-<name>` from PATH.
	"--config": {},
	// --host / -H: redirects the client at an attacker-controlled daemon.
	// Remote daemons are privileged — a malicious --host tcp://evil causes
	// the CLI to auth-negotiate against the attacker's server.
	"--host": {},
	"-H":     {},
	// --context: selects a named context that may itself point --host /
	// identity at attacker infra (user contexts live in ~/.docker/contexts).
	"--context": {},
}

func dockerHandler(tokens []string) (bool, string) {
	base := tokens[0]
	if len(tokens) < 2 {
		return false, ""
	}
	if hasDangerousFlag(tokens, dockerDangerousFlags) {
		return false, ""
	}
	actionIdx := dockerFindActionIdx(tokens)
	if actionIdx >= len(tokens) {
		return false, ""
	}
	action := tokens[actionIdx]
	var rest []string
	if actionIdx+1 < len(tokens) {
		rest = tokens[actionIdx+1:]
	}

	// docker-compose / docker compose.
	if action == "compose" || base == "docker-compose" || base == "podman-compose" {
		if dockerCheckCompose(tokens, actionIdx) {
			return true, base + " compose"
		}
		return false, ""
	}

	if _, hasSub := dockerSafeSubcommands[action]; hasSub {
		sub := dockerFirstNonFlag(rest)
		if sub != "" {
			if action == "buildx" && sub == "imagetools" {
				// Nested subcommand.
				var subRest []string
				for i, t := range rest {
					if t == sub && i+1 < len(rest) {
						subRest = rest[i+1:]
						break
					}
				}
				nested := dockerFirstNonFlag(subRest)
				if nested == "inspect" {
					return true, base + " buildx imagetools inspect"
				}
				return false, ""
			}
			if _, safe := dockerSafeSubcommands[action][sub]; safe {
				// image save -o writes to file.
				if action == "image" && sub == "save" && dockerHasOutputFlag(rest) {
					return false, ""
				}
				return true, base + " " + action + " " + sub
			}
			if _, bad := dockerUnsafeSubcommands[action][sub]; bad {
				return false, ""
			}
		}
	}

	if _, safe := dockerSafeActions[action]; safe {
		// export/save with -o write to file.
		if (action == "export" || action == "save") && dockerHasOutputFlag(rest) {
			return false, ""
		}
		return true, base + " " + action
	}

	if action == "exec" {
		inner := dockerExtractExecInner(rest)
		if inner == nil {
			return false, ""
		}
		if analyzeInnerTokens(inner) {
			return true, base + " exec"
		}
		return false, ""
	}

	return false, ""
}

// -----------------------------------------------------------------------------
// kubectl. Port of src/dippy/cli/kubectl.py. exec delegates.
// -----------------------------------------------------------------------------

var kubectlSafeActions = map[string]struct{}{
	"get": {}, "describe": {}, "explain": {}, "logs": {}, "top": {},
	"cluster-info": {}, "version": {}, "api-resources": {}, "api-versions": {},
	"config": {}, "auth": {}, "wait": {}, "diff": {},
	"plugin": {}, "completion": {}, "kustomize": {},
}

var kubectlSafeSubcommands = map[string]map[string]struct{}{
	"config": {
		"view": {}, "get-contexts": {}, "get-clusters": {},
		"current-context": {}, "get-users": {},
	},
	"auth":    {"can-i": {}, "whoami": {}},
	"rollout": {"status": {}, "history": {}},
}

var kubectlUnsafeSubcommands = map[string]map[string]struct{}{
	"config": {
		"set":            {},
		"set-context":    {},
		"set-cluster":    {},
		"set-credentials": {},
		"delete-context": {},
		"delete-cluster": {},
		"delete-user":    {},
		"use-context":    {},
		"use":            {},
		"rename-context": {},
	},
	"rollout": {"restart": {}, "pause": {}, "resume": {}, "undo": {}},
}

var kubectlFlagsWithArg = map[string]struct{}{
	"-n": {}, "--namespace": {},
	"-l": {}, "--selector": {},
	"-o": {}, "--output": {},
	"--context": {}, "--cluster": {},
	"-f": {}, "--filename": {},
}

var kubectlDangerousFlags = map[string]struct{}{
	// --kubeconfig: exec plugin in kubeconfig runs at cred-retrieval time.
	"--kubeconfig": {},
	// --server: sends traffic to an attacker API server (equivalent to the
	// --kube-apiserver vector blocked in helmDangerousFlags).
	"--server": {},
	// Credential overrides — point kubectl at attacker-chosen identity
	// material, some of which (token, client-certificate) can be used to
	// exfiltrate when combined with a recording attacker server.
	"--token":              {},
	"--client-certificate": {},
	"--client-key":         {},
	"--certificate-authority": {},
}

func kubectlHandler(tokens []string) (bool, string) {
	base := tokens[0]
	if len(tokens) < 2 {
		return false, ""
	}
	if hasDangerousFlag(tokens, kubectlDangerousFlags) {
		return false, ""
	}
	i := 1
	var action string
	for i < len(tokens) {
		t := tokens[i]
		if strings.HasPrefix(t, "-") {
			if _, ok := kubectlFlagsWithArg[t]; ok && i+1 < len(tokens) {
				i += 2
				continue
			}
			i++
			continue
		}
		action = t
		break
	}
	if action == "" {
		return false, ""
	}
	var rest []string
	if i+1 < len(tokens) {
		rest = tokens[i+1:]
	}

	if subs, ok := kubectlSafeSubcommands[action]; ok && len(rest) > 0 {
		for _, t := range rest {
			if !strings.HasPrefix(t, "-") {
				if _, safe := subs[t]; safe {
					return true, base + " " + action + " " + t
				}
				break
			}
		}
	}
	if subs, ok := kubectlUnsafeSubcommands[action]; ok && len(rest) > 0 {
		for _, t := range rest {
			if !strings.HasPrefix(t, "-") {
				if _, bad := subs[t]; bad {
					return false, ""
				}
				break
			}
		}
	}
	if _, safe := kubectlSafeActions[action]; safe {
		return true, base + " " + action
	}
	if action == "exec" {
		// kubectl exec uses -- separator.
		sepIdx := -1
		for i, t := range rest {
			if t == "--" {
				sepIdx = i
				break
			}
		}
		if sepIdx < 0 || sepIdx+1 >= len(rest) {
			return false, ""
		}
		inner := rest[sepIdx+1:]
		if analyzeInnerTokens(inner) {
			return true, base + " exec"
		}
		return false, ""
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// helm. Port of src/dippy/cli/helm.py.
// -----------------------------------------------------------------------------

var helmFlagsWithArg = map[string]struct{}{
	"-n": {}, "--namespace": {},
	"--kube-context":    {},
	"--kube-apiserver":  {},
	"--kube-as-user":    {},
	"--kube-ca-file":    {},
	"--kube-token":      {},
	"--kubeconfig":      {},
	"--registry-config":   {},
	"--repository-cache":  {},
	"--repository-config": {},
	"--content-cache":     {},
	"--burst-limit":       {},
	"--qps":               {},
	"--kube-tls-server-name": {},
}

var helmSafeCommands = map[string]struct{}{
	"completion": {}, "env": {}, "get": {}, "help": {},
	"history": {}, "lint": {}, "list": {}, "ls": {},
	"search": {}, "show": {}, "inspect": {}, "status": {},
	"template": {}, "verify": {}, "version": {},
}

var helmUnsafeCommands = map[string]struct{}{
	"create": {}, "install": {}, "package": {}, "pull": {},
	"fetch": {}, "push": {}, "rollback": {}, "test": {},
	"uninstall": {}, "delete": {}, "del": {}, "un": {}, "upgrade": {},
}

var helmNestedCommands = map[string]struct{}{
	"dependency": {}, "dep": {}, "plugin": {}, "registry": {}, "repo": {},
}

var helmSafeSubcommands = map[string]map[string]struct{}{
	"dependency": {"list": {}, "ls": {}},
	"dep":        {"list": {}, "ls": {}},
	"plugin":     {"list": {}, "ls": {}, "verify": {}},
	"repo":       {"list": {}, "ls": {}},
}

var helmUnsafeSubcommands = map[string]map[string]struct{}{
	"dependency": {"build": {}, "update": {}, "up": {}},
	"dep":        {"build": {}, "update": {}, "up": {}},
	"plugin":     {"install": {}, "uninstall": {}, "update": {}, "package": {}},
	"registry":   {"login": {}, "logout": {}},
	"repo":       {"add": {}, "remove": {}, "rm": {}, "update": {}, "up": {}, "index": {}},
}

var helmDangerousFlags = map[string]struct{}{
	// Same threat model as kubectl: kubeconfig exec plugin, arbitrary
	// API server, attacker-controlled CA bundle.
	"--kubeconfig":     {},
	"--kube-apiserver": {},
	"--kube-ca-file":   {},
	"--kube-token":     {},
	// OCI/registry config files can carry attacker-specified credHelpers
	// or point auth at a capturing server.
	"--registry-config":   {},
	"--repository-config": {},
}

func helmHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	if hasDangerousFlag(tokens, helmDangerousFlags) {
		return false, ""
	}
	idx := 1
	for idx < len(tokens) {
		t := tokens[idx]
		if strings.HasPrefix(t, "-") {
			if _, ok := helmFlagsWithArg[t]; ok && idx+1 < len(tokens) {
				idx += 2
				continue
			}
			if strings.HasPrefix(t, "--kube-as-group") && idx+1 < len(tokens) {
				idx += 2
				continue
			}
			idx++
			continue
		}
		break
	}
	if idx >= len(tokens) {
		return false, ""
	}
	action := tokens[idx]
	var rest []string
	if idx+1 < len(tokens) {
		rest = tokens[idx+1:]
	}
	// --help anywhere.
	for _, t := range tokens {
		if t == "--help" || t == "-h" {
			return true, "helm " + action
		}
	}
	if action == "--help" || action == "-h" || action == "--version" {
		return true, "helm " + action
	}
	if _, ok := helmSafeCommands[action]; ok {
		return true, "helm " + action
	}
	// Dry-run on install/upgrade/uninstall/rollback.
	switch action {
	case "install", "upgrade", "uninstall", "delete", "del", "un", "rollback":
		for _, t := range rest {
			if t == "--dry-run" || strings.HasPrefix(t, "--dry-run=") {
				return true, "helm " + action + " --dry-run"
			}
		}
		return false, ""
	}
	if _, nested := helmNestedCommands[action]; nested {
		var sub string
		for _, t := range rest {
			if strings.HasPrefix(t, "-") {
				continue
			}
			sub = t
			break
		}
		if sub == "" {
			return false, ""
		}
		if subs, ok := helmSafeSubcommands[action]; ok {
			if _, safe := subs[sub]; safe {
				return true, "helm " + action + " " + sub
			}
		}
		return false, ""
	}
	if _, bad := helmUnsafeCommands[action]; bad {
		return false, ""
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// terraform / tofu. Port of src/dippy/cli/terraform.py.
// -----------------------------------------------------------------------------

var terraformSafeActions = map[string]struct{}{
	"version": {}, "help": {}, "fmt": {}, "validate": {},
	"plan": {}, "show": {}, "state": {}, "output": {},
	"graph": {}, "providers": {}, "console": {}, "workspace": {},
	"get": {}, "modules": {}, "metadata": {}, "test": {}, "refresh": {},
}

var terraformSafeSubcommands = map[string]map[string]struct{}{
	"state":     {"list": {}, "show": {}, "pull": {}},
	"workspace": {"list": {}, "show": {}, "select": {}},
}

var terraformUnsafeSubcommands = map[string]map[string]struct{}{
	"state":     {"mv": {}, "rm": {}, "push": {}, "replace-provider": {}},
	"workspace": {"new": {}, "delete": {}},
}

func terraformHandler(tokens []string) (bool, string) {
	base := tokens[0]
	if len(tokens) < 2 {
		return false, ""
	}
	for _, t := range tokens {
		if t == "-help" || t == "--help" || t == "-h" {
			return true, base + " --help"
		}
	}
	i := 1
	var action string
	for i < len(tokens) {
		t := tokens[i]
		if strings.HasPrefix(t, "-") {
			// terraform uses single-dash long flags like -chdir=.
			if t == "-chdir" || t == "-var" || t == "-var-file" {
				i += 2
				continue
			}
			i++
			continue
		}
		action = t
		break
	}
	if action == "" {
		return false, ""
	}
	var rest []string
	if i+1 < len(tokens) {
		rest = tokens[i+1:]
	}
	if subs, ok := terraformSafeSubcommands[action]; ok && len(rest) > 0 {
		for _, t := range rest {
			if !strings.HasPrefix(t, "-") {
				if _, safe := subs[t]; safe {
					return true, base + " " + action + " " + t
				}
				if bad, ok := terraformUnsafeSubcommands[action]; ok {
					if _, isBad := bad[t]; isBad {
						return false, ""
					}
				}
				break
			}
		}
	}
	if bad, ok := terraformUnsafeSubcommands[action]; ok && len(rest) > 0 {
		for _, t := range rest {
			if !strings.HasPrefix(t, "-") {
				if _, isBad := bad[t]; isBad {
					return false, ""
				}
				break
			}
		}
	}
	if _, ok := terraformSafeActions[action]; ok {
		return true, base + " " + action
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// cdk. Port of src/dippy/cli/cdk.py.
// -----------------------------------------------------------------------------

var cdkSafeActions = map[string]struct{}{
	"list": {}, "ls": {}, "diff": {}, "synth": {}, "synthesize": {},
	"metadata": {}, "docs": {}, "doctor": {}, "notices": {},
	"acknowledge": {}, "ack": {},
}

func cdkHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	action := tokens[1]
	if action == "context" {
		for _, t := range tokens {
			if t == "--reset" || t == "--clear" {
				return false, ""
			}
		}
		return true, "cdk context"
	}
	if _, ok := cdkSafeActions[action]; ok {
		return true, "cdk " + action
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// npm / yarn / pnpm. Port of src/dippy/cli/npm.py.
// -----------------------------------------------------------------------------

var npmSafeActions = map[string]struct{}{
	"list": {}, "ls": {}, "ll": {}, "la": {},
	"info": {}, "show": {}, "view": {}, "v": {},
	"search": {}, "s": {}, "find": {},
	"outdated":    {},
	"help":        {},
	"help-search": {},
	"-v":          {}, "--version": {},
	"get":     {},
	"root":    {}, "prefix": {}, "bin": {},
	"docs": {}, "home": {}, "bugs": {}, "repo": {},
	"whoami":   {},
	"ping":     {},
	"explain":  {}, "why": {},
	"pack":       {},
	"fund":       {},
	"doctor":     {},
	"licenses":   {},
	"completion": {},
	"diff":       {},
	"find-dupes": {},
	"query":      {},
	"stars":      {},
	"sbom":       {},
}

var npmSafeSubcommands = map[string]map[string]struct{}{
	"config":   {"list": {}, "ls": {}, "get": {}},
	"cache":    {"ls": {}, "list": {}},
	"run":      {"--list": {}},
	"access":   {"list": {}, "get": {}},
	"dist-tag": {"ls": {}},
	"token":    {"list": {}},
	"profile":  {"get": {}},
	"pkg":      {"get": {}},
	"owner":    {"ls": {}},
}

var npmUnsafeSubcommands = map[string]map[string]struct{}{
	"config":   {"set": {}, "delete": {}, "edit": {}},
	"cache":    {"clean": {}, "add": {}, "verify": {}},
	"access":   {"set": {}, "grant": {}, "revoke": {}},
	"dist-tag": {"add": {}, "rm": {}},
	"token":    {"create": {}, "revoke": {}},
	"profile":  {"set": {}, "enable-2fa": {}, "disable-2fa": {}},
	"pkg":      {"set": {}, "delete": {}, "fix": {}},
	"owner":    {"add": {}, "rm": {}},
	"audit":    {"fix": {}},
	"version":  {"major": {}, "minor": {}, "patch": {}, "premajor": {}, "preminor": {}, "prepatch": {}, "prerelease": {}},
}

var npmDangerousFlags = map[string]struct{}{
	// --userconfig / --globalconfig point at an .npmrc whose directives
	// (init-module, prefix with scripts, etc.) can trigger script
	// execution on subsequent npm invocations.
	"--userconfig":   {},
	"--globalconfig": {},
}

func npmHandler(tokens []string) (bool, string) {
	base := tokens[0]
	if len(tokens) < 2 {
		return false, ""
	}
	if hasDangerousFlag(tokens, npmDangerousFlags) {
		return false, ""
	}
	action := tokens[1]
	var rest []string
	if len(tokens) > 2 {
		rest = tokens[2:]
	}

	if action == "run" {
		if len(rest) == 0 {
			return true, base + " run"
		}
		for _, t := range rest {
			if t == "--list" {
				return true, base + " run"
			}
		}
		return false, ""
	}
	if action == "version" {
		if len(rest) == 0 {
			return true, base + " version"
		}
		return false, ""
	}
	if action == "audit" {
		if len(rest) > 0 && rest[0] == "fix" {
			return false, ""
		}
		return true, base + " audit"
	}
	if action == "config" || action == "c" {
		if len(rest) > 0 {
			sub := rest[0]
			if _, safe := npmSafeSubcommands["config"][sub]; safe {
				return true, base + " config " + sub
			}
			if _, bad := npmUnsafeSubcommands["config"][sub]; bad {
				return false, ""
			}
		}
		return true, base + " config"
	}

	if _, hasSafe := npmSafeSubcommands[action]; hasSafe {
		if len(rest) > 0 {
			sub := rest[0]
			if _, safe := npmSafeSubcommands[action][sub]; safe {
				return true, base + " " + action + " " + sub
			}
			if bad, ok := npmUnsafeSubcommands[action]; ok {
				if _, isBad := bad[sub]; isBad {
					return false, ""
				}
			}
		}
		if action == "owner" {
			return true, base + " owner"
		}
		return false, ""
	}

	if _, hasOnlyUnsafe := npmUnsafeSubcommands[action]; hasOnlyUnsafe {
		if _, hasSafe := npmSafeSubcommands[action]; !hasSafe {
			return false, ""
		}
	}

	if _, ok := npmSafeActions[action]; ok {
		return true, base + " " + action
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// pip / pip3 / uv pip. Port of src/dippy/cli/pip.py.
// -----------------------------------------------------------------------------

var pipSafeActions = map[string]struct{}{
	"list":    {},
	"freeze":  {},
	"show":    {},
	"search":  {},
	"check":   {},
	"config":  {},
	"help":    {}, "-h": {}, "--help": {},
	"version": {}, "-V": {}, "--version": {},
	"debug":   {},
	"cache":   {},
	"index":   {},
	"inspect": {},
	"hash":    {},
}

var pipSafeSubcommands = map[string]map[string]struct{}{
	"cache":  {"dir": {}, "info": {}, "list": {}},
	"config": {"list": {}, "get": {}, "debug": {}},
	"pip":    {"list": {}, "freeze": {}, "show": {}, "check": {}},
}

var pipUnsafeSubcommands = map[string]map[string]struct{}{
	"cache":  {"purge": {}, "remove": {}},
	"config": {"set": {}, "unset": {}, "edit": {}},
	"pip":    {"install": {}, "uninstall": {}},
}

func pipHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	base := tokens[0]
	action := tokens[1]
	var rest []string
	if len(tokens) > 2 {
		rest = tokens[2:]
	}
	desc := base + " " + action

	if subs, ok := pipSafeSubcommands[action]; ok && len(rest) > 0 {
		for _, t := range rest {
			if !strings.HasPrefix(t, "-") {
				if _, safe := subs[t]; safe {
					return true, desc + " " + t
				}
				break
			}
		}
	}
	if subs, ok := pipUnsafeSubcommands[action]; ok && len(rest) > 0 {
		for _, t := range rest {
			if !strings.HasPrefix(t, "-") {
				if _, bad := subs[t]; bad {
					return false, ""
				}
				break
			}
		}
	}
	if _, ok := pipSafeActions[action]; ok {
		return true, desc
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// cargo. Port of src/dippy/cli/cargo.py.
// -----------------------------------------------------------------------------

var cargoSafeActions = map[string]struct{}{
	"help":    {},
	"-h":      {}, "--help": {},
	"version": {}, "-V": {}, "--version": {},
	"search":          {},
	"info":            {},
	"tree":            {},
	"metadata":        {},
	"read-manifest":   {},
	"locate-project":  {},
	"pkgid":           {},
	"verify-project":  {},
	"check":           {}, "c": {},
	"clippy":          {},
	"fmt":             {},
	"doc":             {},
	"fetch":           {},
	"generate-lockfile": {},
	"update":          {},
	"vendor":          {},
	"login":           {},
	"logout":          {},
	"owner":           {},
}

func cargoHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	action := tokens[1]
	if _, ok := cargoSafeActions[action]; ok {
		return true, "cargo " + action
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// brew. Port of src/dippy/cli/brew.py.
// -----------------------------------------------------------------------------

var brewSafeActions = map[string]struct{}{
	"list": {}, "ls": {}, "leaves": {},
	"info": {}, "desc": {}, "home": {}, "homepage": {},
	"deps": {}, "uses": {}, "options": {},
	"search": {}, "doctor": {}, "config": {}, "outdated": {},
	"dr": {}, "-S": {},
	"missing":   {},
	"tap-info":  {},
	"formulae":  {}, "casks": {},
	"log":       {},
	"cat":       {},
	"commands":  {},
	"fetch":     {},
	"docs":      {},
	"shellenv":  {},
	"--version": {}, "-v": {}, "help": {},
}

var brewSafeGlobalFlags = map[string]struct{}{
	"--cache": {}, "--cellar": {}, "--caskroom": {},
	"--prefix": {}, "--repository": {}, "--repo": {},
	"--env":  {},
	"--taps": {}, "--config": {},
}

var brewSafeSubcommands = map[string]map[string]struct{}{
	"cask":   {"list": {}, "info": {}, "search": {}, "outdated": {}, "home": {}},
	"bundle": {"check": {}, "list": {}},
}

var brewUnsafeSubcommands = map[string]map[string]struct{}{
	"cask":     {"install": {}, "uninstall": {}, "upgrade": {}, "zap": {}},
	"services": {"start": {}, "stop": {}, "restart": {}, "run": {}, "cleanup": {}},
	"bundle":   {"install": {}, "dump": {}, "cleanup": {}, "exec": {}},
}

func brewHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	action := tokens[1]
	var rest []string
	if len(tokens) > 2 {
		rest = tokens[2:]
	}
	if _, ok := brewSafeGlobalFlags[action]; ok {
		return true, "brew " + action
	}
	if subs, ok := brewSafeSubcommands[action]; ok && len(rest) > 0 {
		sub := dockerFirstNonFlag(rest)
		if _, safe := subs[sub]; safe {
			return true, "brew " + action + " " + sub
		}
	}
	if subs, ok := brewUnsafeSubcommands[action]; ok && len(rest) > 0 {
		sub := dockerFirstNonFlag(rest)
		if _, bad := subs[sub]; bad {
			return false, ""
		}
		if action == "services" {
			return false, ""
		}
	}
	if action == "services" || action == "bundle" {
		return false, ""
	}
	if action == "analytics" {
		if len(rest) > 0 {
			sub := dockerFirstNonFlag(rest)
			if sub == "on" || sub == "off" {
				return false, ""
			}
		}
		return true, "brew analytics"
	}
	if _, ok := brewSafeActions[action]; ok {
		return true, "brew " + action
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// wget. Port of src/dippy/cli/wget.py. Only --spider or -O /dev/null etc.
// -----------------------------------------------------------------------------

func wgetHandler(tokens []string) (bool, string) {
	for _, t := range tokens {
		if t == "--spider" {
			return true, "wget --spider"
		}
	}
	// -O or --output-document target must be a safe redirect target.
	for i, t := range tokens {
		var target string
		switch {
		case t == "-O" && i+1 < len(tokens):
			target = tokens[i+1]
		case t == "--output-document" && i+1 < len(tokens):
			target = tokens[i+1]
		case strings.HasPrefix(t, "--output-document="):
			target = t[len("--output-document="):]
		}
		if target != "" {
			if _, safe := safeRedirectTargets[target]; safe {
				return true, "wget -O"
			}
			return false, ""
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// black / isort. Python formatters — modify files by default; read-only
// when --check/--diff (black) or --check-only/-c/-d/--diff (isort).
// Port of src/dippy/cli/{black,isort}.py.
// -----------------------------------------------------------------------------

func blackHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if t == "--check" || t == "--diff" {
			return true, "black " + t
		}
	}
	return false, ""
}

func isortHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		switch t {
		case "--check-only", "--check", "-c", "--diff", "-d":
			return true, "isort " + t
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// ruff. Allow everything except `format` / `clean` actions and --fix/--fix-only
// modifier flags. Port of src/dippy/cli/ruff.py.
// -----------------------------------------------------------------------------

func ruffHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return true, "ruff"
	}
	action := tokens[1]
	if action == "format" || action == "clean" {
		return false, ""
	}
	for _, t := range tokens {
		if t == "--fix" || t == "--fix-only" {
			return false, ""
		}
	}
	return true, "ruff " + action
}

// -----------------------------------------------------------------------------
// pytest. Executes Python test code, so default is not safe. Only a tight
// set of read-only flags gets through. Port of src/dippy/cli/pytest.py.
// -----------------------------------------------------------------------------

var pytestSafeFlags = map[string]struct{}{
	"--version":      {},
	"-V":             {},
	"--help":         {},
	"-h":             {},
	"--collect-only": {},
	"--co":           {},
}

func pytestHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if _, ok := pytestSafeFlags[t]; ok {
			return true, "pytest " + t
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// pre-commit. Almost everything modifies hooks or files; only validate-config,
// validate-manifest, and help are safe. Port of src/dippy/cli/pre_commit.py.
// -----------------------------------------------------------------------------

var preCommitSafeActions = map[string]struct{}{
	"validate-config":   {},
	"validate-manifest": {},
	"help":              {},
}

func preCommitHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return true, "pre-commit"
	}
	action := tokens[1]
	if _, ok := preCommitSafeActions[action]; ok {
		return true, "pre-commit " + action
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// openssl. Gate subcommands — version/help/list are always safe,
// x509 is safe with -noout (viewing), s_client is safe (connection testing).
// Port of src/dippy/cli/openssl.py.
// -----------------------------------------------------------------------------

var opensslSafeSubcommands = map[string]struct{}{
	"version": {}, "help": {}, "list": {},
}

func opensslHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	sub := tokens[1]
	if _, ok := opensslSafeSubcommands[sub]; ok {
		return true, "openssl " + sub
	}
	if sub == "x509" {
		for _, t := range tokens {
			if t == "-noout" {
				return true, "openssl x509"
			}
		}
		return false, ""
	}
	if sub == "s_client" {
		return true, "openssl s_client"
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// yq. Outputs to stdout by default; -i / --inplace mutates files.
// Port of src/dippy/cli/yq.py.
// -----------------------------------------------------------------------------

func yqHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if t == "-i" || t == "--inplace" {
			return false, ""
		}
		if strings.HasPrefix(t, "-i=") || strings.HasPrefix(t, "--inplace=") {
			return false, ""
		}
	}
	return true, "yq"
}

// -----------------------------------------------------------------------------
// xxd. Hex dump is read-only; -r (revert) writes binary files.
// Port of src/dippy/cli/xxd.py.
// -----------------------------------------------------------------------------

func xxdHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if t == "-r" || t == "-revert" {
			return false, ""
		}
	}
	return true, "xxd"
}

// -----------------------------------------------------------------------------
// mktemp. Creates files; -u is dry-run (just prints a name).
// Port of src/dippy/cli/mktemp.py.
// -----------------------------------------------------------------------------

func mktempHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if t == "-u" {
			return true, "mktemp -u"
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// gzip / gunzip. Compresses in place by default. Safe when --stdout / -c,
// --list / -l, --test / -t, --help, --version (including combined short
// flags like -lv, -tv, -dc). Port of src/dippy/cli/gzip.py.
// -----------------------------------------------------------------------------

var gzipSafeFlags = map[string]struct{}{
	"-c": {}, "--stdout": {}, "--to-stdout": {},
	"-l": {}, "--list": {},
	"-t": {}, "--test": {},
	"--help": {}, "--version": {},
}

// gzipSafeShortChars are the single-letter short flags whose presence
// anywhere in a combined short-flag run makes the invocation safe.
var gzipSafeShortChars = map[byte]struct{}{
	'c': {}, 'l': {}, 't': {},
}

func gzipHandler(tokens []string) (bool, string) {
	base := tokens[0]
	for _, t := range tokens[1:] {
		if _, ok := gzipSafeFlags[t]; ok {
			return true, base
		}
		if strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && len(t) > 1 {
			for i := 1; i < len(t); i++ {
				if _, ok := gzipSafeShortChars[t[i]]; ok {
					return true, base
				}
			}
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// tar. Only listing (-t/--list) is safe. --to-command delegates to the
// inner command. Port of src/dippy/cli/tar.py.
// -----------------------------------------------------------------------------

func tarHandler(tokens []string) (bool, string) {
	// --to-command delegation must win — it's the most specific signal.
	for i, t := range tokens[1:] {
		if strings.HasPrefix(t, "--to-command=") {
			inner := t[len("--to-command="):]
			ok, _ := IsLocallySafe(inner)
			if ok {
				return true, "tar --to-command"
			}
			return false, ""
		}
		if t == "--to-command" && i+2 < len(tokens) {
			inner := tokens[i+2]
			ok, _ := IsLocallySafe(inner)
			if ok {
				return true, "tar --to-command"
			}
			return false, ""
		}
	}

	// Detect operation. Long flags first.
	for _, t := range tokens[1:] {
		switch t {
		case "--list":
			return true, "tar list"
		case "--create", "--extract", "--get", "--append", "--update", "--delete":
			return false, ""
		}
	}
	// Short flags (combined like -cvf, -xzf).
	for _, t := range tokens[1:] {
		if !strings.HasPrefix(t, "-") || strings.HasPrefix(t, "--") {
			continue
		}
		for i := 1; i < len(t); i++ {
			switch t[i] {
			case 't':
				return true, "tar list"
			case 'c', 'x', 'r', 'u':
				return false, ""
			}
		}
	}
	// Old-style first arg without dash: "tf archive", "cvf archive.tgz".
	if len(tokens) > 1 && !strings.HasPrefix(tokens[1], "-") {
		arg := tokens[1]
		for i := 0; i < len(arg); i++ {
			switch arg[i] {
			case 't':
				return true, "tar list"
			case 'c', 'x', 'r', 'u':
				return false, ""
			}
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// env. Delegates to the inner command (after skipping flags and VAR=value
// assignments). Port of src/dippy/cli/env.py.
// -----------------------------------------------------------------------------

var envFlagsWithArg = map[string]struct{}{
	"-u": {}, "--unset": {},
	"-S": {}, "--split-string": {},
	"-C": {}, "--chdir": {},
}

func envHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return true, "env"
	}
	i := 1
	for i < len(tokens) {
		t := tokens[i]
		if t == "--" {
			i++
			break
		}
		if _, ok := envFlagsWithArg[t]; ok {
			i += 2
			continue
		}
		if strings.HasPrefix(t, "-") {
			i++
			continue
		}
		if eq := strings.IndexByte(t, '='); eq > 0 {
			// Mirror localallow.isSafeAssign: reject dangerous env-var names
			// (GIT_SSH_COMMAND, LD_PRELOAD, etc.) at fast-allow time. Without
			// this, `env GIT_SSH_COMMAND='id' git fetch` gets approved because
			// envHandler strips assignments and delegates to the inner cmd.
			name := t[:eq]
			if isDangerousEnvName(name) {
				return false, ""
			}
			i++
			continue
		}
		break
	}
	if i >= len(tokens) {
		return true, "env"
	}
	inner := tokens[i:]
	if analyzeInnerTokens(inner) {
		return true, "env " + inner[0]
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// shell: bash / sh / zsh / dash / ksh / fish. Interactive invocations
// are rejected; -c <cmd> delegates to the quoted inner string.
// Port of src/dippy/cli/shell.py.
// -----------------------------------------------------------------------------

func shellHandler(tokens []string) (bool, string) {
	base := tokens[0]
	if len(tokens) < 2 {
		return false, ""
	}
	cIdx := -1
	for i, t := range tokens {
		if !strings.HasPrefix(t, "-") || strings.HasPrefix(t, "--") {
			continue
		}
		// Combined short-flag form (-lc, -ic, -xc, …). Reject any combination
		// containing `i` or `l` — these turn the shell interactive or login,
		// sourcing ~/.bashrc or ~/.profile before the -c string runs.
		flags := t[1:]
		if !strings.ContainsRune(flags, 'c') {
			continue
		}
		if strings.ContainsRune(flags, 'i') || strings.ContainsRune(flags, 'l') {
			return false, ""
		}
		cIdx = i
		break
	}
	// Reject unsupported long flags that source rc files or change the
	// startup behavior around -c.
	for _, t := range tokens[1:] {
		switch t {
		case "--login", "--interactive", "--rcfile", "--init-file", "--posix":
			return false, ""
		}
	}
	if cIdx == -1 || cIdx+1 >= len(tokens) {
		return false, ""
	}
	inner := tokens[cIdx+1]
	if inner == "" {
		return false, ""
	}
	ok, _ := IsLocallySafe(inner)
	if ok {
		return true, base + " -c"
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// fd. File search is always safe; -x/-X/--exec/--exec-batch delegate to
// the inner command. Port of src/dippy/cli/fd.py.
// -----------------------------------------------------------------------------

var fdExecFlags = map[string]struct{}{
	"-x": {}, "--exec": {},
	"-X": {}, "--exec-batch": {},
}

func fdHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return true, "fd"
	}
	execIdx := -1
	for i, t := range tokens[1:] {
		if _, ok := fdExecFlags[t]; ok {
			execIdx = i + 1
			break
		}
	}
	if execIdx == -1 {
		return true, "fd"
	}
	if execIdx+1 >= len(tokens) {
		return false, ""
	}
	inner := tokens[execIdx+1:]
	// fd may include trailing `;` or `{}` placeholders; strip them for analysis.
	var trimmed []string
	for _, t := range inner {
		if t == ";" {
			break
		}
		trimmed = append(trimmed, t)
	}
	if len(trimmed) == 0 {
		return false, ""
	}
	if analyzeInnerTokens(trimmed) {
		return true, "fd " + tokens[execIdx]
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// open (macOS). Launches external apps by default; -R reveals in Finder
// without launching. Port of src/dippy/cli/open.py.
// -----------------------------------------------------------------------------

func openHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if t == "-R" {
			return true, "open -R"
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// sort. Text processing is safe; `-o` / `--output` writes to a file, which
// must be a safe redirect target (e.g. /dev/null, -, /dev/stdout). Port of
// src/dippy/cli/sort.py — Dippy uses its redirect_targets facility; we
// enforce the equivalent check inline.
// -----------------------------------------------------------------------------

func sortHandler(tokens []string) (bool, string) {
	for i := 1; i < len(tokens); i++ {
		t := tokens[i]
		var target string
		switch {
		case t == "-o" && i+1 < len(tokens):
			target = tokens[i+1]
		case strings.HasPrefix(t, "-o") && !strings.HasPrefix(t, "--") && len(t) > 2:
			target = t[2:]
		case t == "--output" && i+1 < len(tokens):
			target = tokens[i+1]
		case strings.HasPrefix(t, "--output="):
			target = t[len("--output="):]
		}
		if target != "" {
			if _, safe := safeRedirectTargets[target]; safe {
				return true, "sort -o"
			}
			return false, ""
		}
	}
	return true, "sort"
}

// -----------------------------------------------------------------------------
// uv / uvx — Python package manager. Full port of src/dippy/cli/uv.py.
// `uv run <cmd>` delegates; `uv pip <sub>` has its own safe/unsafe table.
// -----------------------------------------------------------------------------

var uvSafeCommands = map[string]struct{}{
	"sync": {}, "lock": {}, "tree": {}, "version": {}, "help": {},
	"--version": {}, "--help": {}, "-v": {}, "-h": {}, "venv": {},
	"export": {},
}

var uvSafeSubcommands = map[string]map[string]struct{}{
	"cache":  {"dir": {}},
	"python": {"list": {}, "find": {}, "dir": {}},
}

var uvUnsafeSubcommands = map[string]map[string]struct{}{
	"cache":  {"clean": {}, "prune": {}},
	"python": {"install": {}, "uninstall": {}, "pin": {}},
}

var uvPipSafe = map[string]struct{}{
	"list": {}, "freeze": {}, "show": {}, "check": {}, "tree": {},
}

var uvPipUnsafe = map[string]struct{}{
	"install": {}, "uninstall": {}, "sync": {}, "compile": {},
}

var uvRunFlagsWithArg = map[string]struct{}{
	"--python": {}, "-p": {},
	"--with": {}, "--with-requirements": {},
	"--project": {}, "--directory": {},
	"--group": {}, "--extra": {}, "--package": {},
}

func uvHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return true, "uv"
	}
	action := tokens[1]
	var rest []string
	if len(tokens) > 2 {
		rest = tokens[2:]
	}

	if _, ok := uvSafeCommands[action]; ok {
		return true, "uv " + action
	}

	if _, hasSafe := uvSafeSubcommands[action]; hasSafe {
		if len(rest) > 0 {
			sub := rest[0]
			if _, safe := uvSafeSubcommands[action][sub]; safe {
				return true, "uv " + action + " " + sub
			}
			if _, bad := uvUnsafeSubcommands[action][sub]; bad {
				return false, ""
			}
		}
		return true, "uv " + action
	}
	if _, hasUnsafe := uvUnsafeSubcommands[action]; hasUnsafe {
		if len(rest) > 0 {
			sub := rest[0]
			if _, bad := uvUnsafeSubcommands[action][sub]; bad {
				return false, ""
			}
		}
		return false, ""
	}

	if action == "pip" {
		if len(rest) == 0 {
			return true, "uv pip"
		}
		sub := rest[0]
		if _, bad := uvPipUnsafe[sub]; bad {
			return false, ""
		}
		if _, safe := uvPipSafe[sub]; safe {
			return true, "uv pip " + sub
		}
		return false, ""
	}

	if action == "run" {
		i := 2
		for i < len(tokens) {
			t := tokens[i]
			if strings.HasPrefix(t, "-") {
				if _, consumes := uvRunFlagsWithArg[t]; consumes && i+1 < len(tokens) {
					i += 2
					continue
				}
				i++
				continue
			}
			break
		}
		if i >= len(tokens) {
			return false, ""
		}
		inner := tokens[i:]
		if analyzeInnerTokens(inner) {
			return true, "uv run " + inner[0]
		}
		return false, ""
	}

	return false, ""
}
