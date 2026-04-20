package fastallow

// Static allowlists used by IsLocallySafe.
//
// Ported 1-to-1 from Dippy's SIMPLE_SAFE / WRAPPER_COMMANDS
// (https://github.com/ldayton/Dippy, MIT-licensed). Items that "behave
// poorly in a hook context" (pagers, interactive monitors, infinite
// builtins) are still allowed here, matching Dippy exactly — yolonot's
// caller (Claude Code) never hands them a TTY, so they either exit fast
// or get killed by the caller. Keeping the list 1-to-1 with Dippy means
// users get identical allow-decisions whether they route through Dippy
// via pre-check or through the built-in fast-allow path.

// safeCommands are commands that read state but never mutate it, so they're
// safe to auto-allow regardless of arguments (within the argument-purity
// constraints enforced by localallow.go: no unsafe substitutions, no
// arbitrary redirects, etc.).
var safeCommands = map[string]struct{}{
	// File content viewing
	"cat": {}, "head": {}, "tail": {}, "less": {}, "more": {},
	"bat": {}, "tac": {}, "od": {}, "hexdump": {}, "strings": {},
	// Compressed file viewers
	"bzcat": {}, "bzmore": {}, "funzip": {}, "lz4cat": {},
	"xzcat": {}, "xzless": {}, "xzmore": {},
	"zcat": {}, "zless": {}, "zmore": {},
	"zstdcat": {}, "zstdless": {},
	// Archive inspection
	"zipinfo": {},
	// Binary analysis
	"dwarfdump": {}, "dyld_info": {}, "ldd": {}, "lsbom": {}, "nm": {},
	"objdump": {}, "otool": {}, "pagestuff": {}, "readelf": {}, "size": {},
	// Directory listing
	"ls": {}, "ll": {}, "la": {}, "tree": {}, "exa": {}, "eza": {},
	"dir": {}, "vdir": {},
	// File & disk info
	"stat": {}, "file": {}, "wc": {}, "du": {}, "df": {},
	// Path utilities
	"basename": {}, "dirname": {}, "pathchk": {}, "pwd": {}, "cd": {},
	"readlink": {}, "realpath": {},
	// Search & find
	"grep": {}, "rg": {}, "ripgrep": {}, "ag": {}, "ack": {},
	"locate": {}, "look": {}, "mdfind": {}, "mdls": {},
	// find is intentionally NOT here — its -exec predicate runs arbitrary
	// commands. Dippy routes find through a dedicated handler; until we
	// port that handler (see task #24), find falls through to the LLM.

	// Text processing. `sort` is handled by sortHandler (gates -o output file).
	"uniq": {}, "cut": {}, "col": {}, "colrm": {}, "column": {}, "comm": {},
	"cmp": {}, "diff": {}, "diff3": {}, "diffstat": {}, "expand": {},
	"fmt": {}, "fold": {}, "jot": {}, "join": {}, "lam": {}, "nl": {},
	"paste": {}, "pr": {}, "rev": {}, "rs": {}, "seq": {}, "tr": {},
	"tsort": {}, "ul": {}, "unexpand": {}, "unvis": {}, "vis": {}, "what": {},
	// Calculators (pure)
	"bc": {}, "dc": {}, "expr": {}, "units": {},
	// Structured data
	"jq": {}, "xq": {},
	// Encoding & checksums
	"base64": {}, "md5sum": {}, "sha1sum": {}, "sha256sum": {}, "sha512sum": {},
	"b2sum": {}, "cksum": {}, "md5": {}, "shasum": {}, "sum": {},
	// User & system info
	"whoami": {}, "hostname": {}, "hostinfo": {}, "uname": {}, "sw_vers": {},
	"id": {}, "finger": {}, "groups": {}, "last": {}, "locale": {}, "logname": {},
	"users": {}, "w": {}, "who": {}, "klist": {},
	// Date & time
	"date": {}, "cal": {}, "ncal": {}, "uptime": {},
	// System configuration (read-only)
	"getconf": {}, "machine": {}, "pagesize": {}, "uuidgen": {},
	// Process & resource monitoring
	"atos": {}, "btop": {}, "footprint": {}, "free": {}, "fs_usage": {},
	"fuser": {}, "heap": {}, "htop": {}, "ioreg": {}, "iostat": {},
	"ipcs": {}, "leaks": {}, "lskq": {}, "lsmp": {}, "lsof": {}, "lsvfs": {},
	"lpstat": {}, "nettop": {}, "pgrep": {}, "powermetrics": {}, "ps": {},
	"system_profiler": {}, "top": {}, "vm_stat": {}, "vmmap": {}, "vmstat": {},
	// Environment & output
	"printenv": {}, "echo": {}, "printf": {},
	// Network diagnostics
	"ping": {}, "host": {}, "dig": {}, "nslookup": {}, "traceroute": {},
	"mtr": {}, "netstat": {}, "ss": {}, "arp": {}, "route": {}, "whois": {},
	// Command lookup & help
	"which": {}, "whereis": {}, "type": {}, "command": {}, "hash": {},
	"apropos": {}, "man": {}, "help": {}, "info": {}, "osalang": {},
	"tldr": {}, "whatis": {},
	// Code quality & linting
	"cloc": {}, "flake8": {}, "mypy": {},
	// Media & image info
	"afinfo": {}, "afplay": {}, "ffprobe": {}, "heif-info": {}, "identify": {},
	"opj_dump": {}, "rdjpgcom": {}, "sndfile-info": {}, "tiffdump": {},
	"tiffinfo": {}, "webpinfo": {},
	// Shell builtins & utilities
	"true": {}, "false": {}, "getopt": {}, "getopts": {}, "shopt": {},
	"sleep": {}, "read": {}, "test": {}, "[": {}, "yes": {},
	// Terminal
	"banner": {}, "clear": {}, "pbpaste": {}, "reset": {}, "tabs": {},
	"tput": {}, "tty": {},
}

// wrapperCommands are transparent wrappers. When encountered as the head,
// we skip past numeric/flag args and recurse into the inner command.
// Ported from Dippy's WRAPPER_COMMANDS. Note: "command" is both a wrapper
// AND in safeCommands — the wrapper logic takes precedence when it has
// arguments that reference another binary. `command -v foo` is always
// allowed as a special case.
var wrapperCommands = map[string]struct{}{
	"time":    {},
	"timeout": {},
	"nice":    {},
	"nohup":   {},
	"strace":  {},
	"ltrace":  {},
	"command": {},
	"builtin": {},
}

// subcommandReadOnly gates multiplex commands (head `go`, second arg is
// the subcommand) to their known read-only subcommand sets. Used only
// for heads that don't have a dedicated cliHandler. Handlers take
// precedence (see localallow.go); entries here for heads owned by a
// handler would be dead code, so they are kept out of this table.
var subcommandReadOnly = map[string]map[string]struct{}{
	"go": {
		"version": {}, "env": {}, "list": {}, "doc": {}, "vet": {},
		"fmt": {}, "help": {},
	},
	"systemctl": {
		"status": {}, "is-active": {}, "is-enabled": {}, "is-failed": {},
		"list-units": {}, "list-unit-files": {}, "list-jobs": {}, "show": {},
		"cat": {}, "get-default": {},
	},
	"pm2": {
		"list": {}, "ls": {}, "status": {}, "describe": {}, "show": {},
		"logs": {}, "monit": {}, "info": {}, "version": {},
	},
}

// needsSubcommandGate returns true if the command head requires the next
// positional arg to be in subcommandReadOnly[head].
func needsSubcommandGate(head string) bool {
	_, ok := subcommandReadOnly[head]
	return ok
}

// isWrapperCommand returns true for transparent wrappers like `time`,
// `timeout`, `nohup` — we re-analyze the inner command.
func isWrapperCommand(head string) bool {
	_, ok := wrapperCommands[head]
	return ok
}

// hasSubcommandLabel reports whether this head is multiplex — a head
// whose reason label should include the next positional arg (subcommand).
// True for both handler-owned heads (git, docker, kubectl, ...) and
// statically gated heads (go, systemctl, pm2). Used only for building
// the user-facing reason string, not for allow decisions.
func hasSubcommandLabel(head string) bool {
	if _, ok := subcommandReadOnly[head]; ok {
		return true
	}
	if _, ok := cliHandlers[head]; ok {
		return true
	}
	return false
}
