package main

import (
	"fmt"
	"io"
	"strings"
)

const defaultBaseURL = "https://secrt.ca"

// Deps holds injectable dependencies for testing.
type Deps struct {
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	HTTPClient  HTTPDoer
	IsTTY       func() bool // stdin is a terminal
	IsStdoutTTY func() bool // stdout is a terminal (controls color)
	Getenv      func(string) string
	Rand        io.Reader
	ReadPass    func(prompt string, w io.Writer) (string, error)
}

// parsedArgs holds parsed global and command-specific flags.
type parsedArgs struct {
	args []string // positional args after flags

	// Global
	baseURL         string
	baseURLFromFlag bool // true if --base-url was explicitly set
	apiKey          string
	json            bool

	// Create
	ttl  string
	text string
	file string

	// Passphrase
	passphrasePrompt bool
	passphraseEnv    string
	passphraseFile   string
}

// run is the main entry point. Returns exit code.
func run(args []string, deps Deps) int {
	if len(args) < 2 {
		printUsage(deps)
		return 2
	}

	// Check for top-level flags
	switch args[1] {
	case "--version", "-v":
		fmt.Fprintf(deps.Stdout, "secrt %s\n", version)
		return 0
	case "--help", "-h":
		printHelp(deps)
		return 0
	}

	command := args[1]
	remaining := args[2:]

	switch command {
	case "version":
		fmt.Fprintf(deps.Stdout, "secrt %s\n", version)
		return 0
	case "help":
		return runHelp(remaining, deps)
	case "completion":
		return runCompletion(remaining, deps)
	case "create":
		return runCreate(remaining, deps)
	case "claim":
		return runClaim(remaining, deps)
	case "burn":
		return runBurn(remaining, deps)
	default:
		fmt.Fprintf(deps.Stderr, "error: unknown command %q\n", command)
		printUsage(deps)
		return 2
	}
}

func runHelp(args []string, deps Deps) int {
	if len(args) == 0 {
		printHelp(deps)
		return 0
	}
	switch args[0] {
	case "create":
		printCreateHelp(deps)
	case "claim":
		printClaimHelp(deps)
	case "burn":
		printBurnHelp(deps)
	default:
		fmt.Fprintf(deps.Stderr, "error: unknown command %q\n", args[0])
		return 2
	}
	return 0
}

func runCompletion(args []string, deps Deps) int {
	if len(args) != 1 {
		fmt.Fprintf(deps.Stderr, "error: specify a shell (supported: bash, zsh, fish)\n")
		return 2
	}
	switch args[0] {
	case "bash":
		fmt.Fprint(deps.Stdout, bashCompletion)
	case "zsh":
		fmt.Fprint(deps.Stdout, zshCompletion)
	case "fish":
		fmt.Fprint(deps.Stdout, fishCompletion)
	default:
		fmt.Fprintf(deps.Stderr, "error: unsupported shell %q (supported: bash, zsh, fish)\n", args[0])
		return 2
	}
	return 0
}

// parseFlags parses command-specific flags from args.
// Returns parsed args and any error.
func parseFlags(args []string, allowedFlags map[string]bool) (parsedArgs, error) {
	var pa parsedArgs
	var positional []string

	i := 0
	for i < len(args) {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			i++
			continue
		}

		switch arg {
		case "--help", "-h":
			pa.args = nil
			return pa, errShowHelp
		case "--json":
			pa.json = true
		case "--base-url":
			if i+1 >= len(args) {
				return pa, fmt.Errorf("--base-url requires a value")
			}
			i++
			pa.baseURL = args[i]
			pa.baseURLFromFlag = true
		case "--api-key":
			if i+1 >= len(args) {
				return pa, fmt.Errorf("--api-key requires a value")
			}
			i++
			pa.apiKey = args[i]
		case "--ttl":
			if i+1 >= len(args) {
				return pa, fmt.Errorf("--ttl requires a value")
			}
			i++
			pa.ttl = args[i]
		case "--text":
			if i+1 >= len(args) {
				return pa, fmt.Errorf("--text requires a value")
			}
			i++
			pa.text = args[i]
		case "--file":
			if i+1 >= len(args) {
				return pa, fmt.Errorf("--file requires a value")
			}
			i++
			pa.file = args[i]
		case "--passphrase-prompt":
			pa.passphrasePrompt = true
		case "--passphrase-env":
			if i+1 >= len(args) {
				return pa, fmt.Errorf("--passphrase-env requires a value")
			}
			i++
			pa.passphraseEnv = args[i]
		case "--passphrase-file":
			if i+1 >= len(args) {
				return pa, fmt.Errorf("--passphrase-file requires a value")
			}
			i++
			pa.passphraseFile = args[i]
		default:
			return pa, fmt.Errorf("unknown flag: %s", arg)
		}
		i++
	}

	pa.args = positional
	return pa, nil
}

var errShowHelp = fmt.Errorf("show help")

// resolveGlobals fills in defaults from env vars.
func resolveGlobals(pa *parsedArgs, deps Deps) {
	if pa.baseURL == "" {
		if env := deps.Getenv("SECRET_BASE_URL"); env != "" {
			pa.baseURL = env
		} else {
			pa.baseURL = defaultBaseURL
		}
	}
	if pa.apiKey == "" {
		if env := deps.Getenv("SECRET_API_KEY"); env != "" {
			pa.apiKey = env
		}
	}
}

// --- Help text ---

func printUsage(deps Deps) {
	c := colorFunc(deps.IsStdoutTTY())
	fmt.Fprintf(deps.Stderr, "%s — one-time secret sharing\n\nRun '%s' for usage.\n",
		c("36", "secrt"), c("36", "secrt help"))
}

func printHelp(deps Deps) {
	c := colorFunc(deps.IsStdoutTTY())
	fmt.Fprintf(deps.Stderr, `%s — one-time secret sharing

%s
  %s %s %s

%s
  %s    Encrypt and upload a secret
  %s     Retrieve and decrypt a secret
  %s      Destroy a secret (requires API key)
  %s   Show version
  %s      Show this help
  %s  Output shell completion script

%s
  %s %s     Server URL (default: https://secrt.ca)
  %s %s      API key for authenticated access
  %s               Output as JSON
  %s           Show help
  %s        Show version

%s
  echo "pw123" | %s %s
  %s https://secrt.ca/s/abc#v1.key
`,
		c("36", "secrt"),
		c("1", "USAGE"),
		c("36", "secrt"), c("36", "<command>"), c("2", "[options]"),
		c("1", "COMMANDS"),
		c("36", "create"),
		c("36", "claim"),
		c("36", "burn"),
		c("36", "version"),
		c("36", "help"),
		c("36", "completion"),
		c("1", "GLOBAL OPTIONS"),
		c("33", "--base-url"), c("2", "<url>"),
		c("33", "--api-key"), c("2", "<key>"),
		c("33", "--json"),
		c("33", "-h, --help"),
		c("33", "-v, --version"),
		c("1", "EXAMPLES"),
		c("36", "secrt"), c("36", "create"),
		c("36", "secrt claim"),
	)
}

func printCreateHelp(deps Deps) {
	c := colorFunc(deps.IsStdoutTTY())
	fmt.Fprintf(deps.Stderr, `%s %s — Encrypt and upload a secret

%s
  %s %s %s

%s
  %s %s         TTL for the secret (e.g., 5m, 2h, 1d)
  %s %s     Secret text (visible in shell history)
  %s %s     Read secret from file
  %s     Prompt for passphrase
  %s %s  Read passphrase from env var
  %s %s  Read passphrase from file
  %s %s     Server URL
  %s %s      API key
  %s               Output as JSON
  %s           Show help

%s
  Reads from stdin by default. Use %s or %s for alternatives.
  Exactly one input source must be selected.

%s
  echo "secret" | %s %s
  %s %s %s "my secret" %s 5m
`,
		c("36", "secrt"), c("36", "create"),
		c("1", "USAGE"),
		c("36", "secrt"), c("36", "create"), c("2", "[options]"),
		c("1", "OPTIONS"),
		c("33", "--ttl"), c("2", "<ttl>"),
		c("33", "--text"), c("2", "<value>"),
		c("33", "--file"), c("2", "<path>"),
		c("33", "--passphrase-prompt"),
		c("33", "--passphrase-env"), c("2", "<name>"),
		c("33", "--passphrase-file"), c("2", "<path>"),
		c("33", "--base-url"), c("2", "<url>"),
		c("33", "--api-key"), c("2", "<key>"),
		c("33", "--json"),
		c("33", "-h, --help"),
		c("1", "INPUT"),
		c("33", "--text"), c("33", "--file"),
		c("1", "EXAMPLES"),
		c("36", "secrt"), c("36", "create"),
		c("36", "secrt"), c("36", "create"), c("33", "--text"), c("33", "--ttl"),
	)
}

func printClaimHelp(deps Deps) {
	c := colorFunc(deps.IsStdoutTTY())
	fmt.Fprintf(deps.Stderr, `%s %s — Retrieve and decrypt a secret

%s
  %s %s %s %s

%s
  %s     Prompt for passphrase
  %s %s  Read passphrase from env var
  %s %s  Read passphrase from file
  %s %s     Server URL
  %s               Output as JSON
  %s           Show help

%s
  %s %s https://secrt.ca/s/abc#v1.key
`,
		c("36", "secrt"), c("36", "claim"),
		c("1", "USAGE"),
		c("36", "secrt"), c("36", "claim"), c("2", "<share-url>"), c("2", "[options]"),
		c("1", "OPTIONS"),
		c("33", "--passphrase-prompt"),
		c("33", "--passphrase-env"), c("2", "<name>"),
		c("33", "--passphrase-file"), c("2", "<path>"),
		c("33", "--base-url"), c("2", "<url>"),
		c("33", "--json"),
		c("33", "-h, --help"),
		c("1", "EXAMPLES"),
		c("36", "secrt"), c("36", "claim"),
	)
}

func printBurnHelp(deps Deps) {
	c := colorFunc(deps.IsStdoutTTY())
	fmt.Fprintf(deps.Stderr, `%s %s — Destroy a secret (requires API key)

%s
  %s %s %s %s

%s
  %s %s      API key (required)
  %s %s     Server URL
  %s               Output as JSON
  %s           Show help

%s
  %s %s test-id %s sk_prefix.secret
`,
		c("36", "secrt"), c("36", "burn"),
		c("1", "USAGE"),
		c("36", "secrt"), c("36", "burn"), c("2", "<id-or-url>"), c("2", "[options]"),
		c("1", "OPTIONS"),
		c("33", "--api-key"), c("2", "<key>"),
		c("33", "--base-url"), c("2", "<url>"),
		c("33", "--json"),
		c("33", "-h, --help"),
		c("1", "EXAMPLES"),
		c("36", "secrt"), c("36", "burn"), c("33", "--api-key"),
	)
}
