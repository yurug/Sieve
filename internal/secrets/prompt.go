package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// PassphraseFileEnv names the environment variable that points to a file
// containing the passphrase. Mirrors the pattern systemd's LoadCredential=
// uses, and lets operators mount a secret file into the container.
const PassphraseFileEnv = "SIEVE_PASSPHRASE_FILE"

// PassphraseFDEnv names the environment variable an operator sets to read the
// passphrase from an already-open file descriptor (e.g. SIEVE_PASSPHRASE_FD=3),
// for supervisor/pipe handoffs that don't touch the filesystem. It is OPT-IN by
// design: earlier builds auto-detected *any* open fd 3, which let a stray
// descriptor leaked by a terminal, IDE, tmux, or CI launcher silently hijack
// passphrase intake — Sieve read whatever that fd pointed at as the passphrase
// and failed startup with a bogus "wrong passphrase", never reaching the TTY
// prompt. Requiring the operator to name the fd removes that footgun; a
// descriptor Sieve wasn't told to use is never read.
const PassphraseFDEnv = "SIEVE_PASSPHRASE_FD"

// PromptOptions controls how Acquire reads the passphrase.
type PromptOptions struct {
	// Confirm, when true, means the caller is capturing a NEW passphrase
	// that needs double-entry verification against typos — first-run
	// setup (--setup) and --rotate-passphrase's new-passphrase prompt both
	// set this. When a machine-provided source (SIEVE_PASSPHRASE_FILE or
	// SIEVE_PASSPHRASE_FD) is configured, Confirm no longer forces a TTY
	// (VPA-X01 fork, queue item #4 "unattended first run"): a static
	// value can't be mistyped, so a single read of that source stands in
	// for both the passphrase and its confirmation, and Acquire logs one
	// line naming which source it used (never the value). Confirm only
	// falls back to requiring a TTY when NEITHER source is configured —
	// see RequireTTY below for the unconditional escape hatch.
	Confirm bool

	// Prompt is the human-facing label printed before the read. Defaults
	// to "Sieve passphrase: ".
	Prompt string

	// RequireTTY, when true, unconditionally skips SIEVE_PASSPHRASE_FILE
	// and SIEVE_PASSPHRASE_FD and reads only from the TTY, regardless of
	// Confirm or whether a source is configured. No current caller sets
	// this explicitly — it exists as an escape hatch for a future flow
	// that must never accept a machine-provided source even when Confirm
	// would otherwise allow one (e.g. two prompts in the same run, like
	// --rotate-passphrase's current+new pair, that must not silently both
	// resolve to the same static source). Acquire errors out if stdin is
	// not a TTY rather than falling back.
	RequireTTY bool
}

// IsStdinTerminal reports whether stdin is connected to a TTY. Centralized
// here so callers outside this package (notably cmd/sieve, which gates the
// destructive --reset-keyring flag on a TTY confirmation) use the same
// check `Acquire` uses below — different definitions of "is a TTY" can
// disagree on edge cases (PTY-wrapped pipes, virtio consoles), and a
// reset path that disagrees with the prompt path is a UX trap.
func IsStdinTerminal() bool {
	return term.IsTerminal(int(syscall.Stdin))
}

// Acquire reads a passphrase using the documented priority order:
// 1. If RequireTTY is set → TTY only, unconditionally (see PromptOptions).
// 2. Else if Confirm is set AND a machine-provided source is configured →
// read that source ONCE and use it as both the passphrase and its
// confirmation (VPA-X01 fork, queue item #4 "unattended first run": a
// static value can't be mistyped, so there is nothing to confirm against).
// One line is logged naming which source satisfied the prompt — never the
// value. This is what lets --setup and --rotate-passphrase's new-passphrase
// prompt run without a TTY.
// 3. Else if Confirm is set (and neither source is configured) → TTY only,
// prompting twice and verifying the two entries match. This is the ONLY
// remaining case that forces a TTY when Confirm is set — the case this
// fork changes is #2 above.
// 4. Else if SIEVE_PASSPHRASE_FILE is set → read that file. Takes precedence
// over the TTY prompt so that operators who've wired up a credential
// file (systemd LoadCredential=, container secret mount, etc.) aren't
// re-prompted on every start. If the path starts with /run/secrets or
// is otherwise an ephemeral mount the operator manages, the file is
// *not* deleted; it's the operator's responsibility. Reading it once
// into memory is enough.
// 5. Else if SIEVE_PASSPHRASE_FD names an open fd → read that descriptor
// until EOF. OPT-IN only: the operator explicitly designates the fd, so a
// descriptor leaked/inherited from a launcher (terminal, IDE, tmux, CI)
// can never silently hijack intake. A named-but-unreadable fd is a loud
// error, not a fallthrough.
// 6. Else if stdin is a TTY → prompt with echo off (golang.org/x/term).
// 7. Else → return an error so startup fails loudly.
// Environment variables (other than the file/fd pointers, which name a
// *location*, not the secret) are deliberately not supported — env leaks
// through /proc/<pid>/environ, ps, and crash dumps. If you need to plumb a
// passphrase from CI, write it to a file and point SIEVE_PASSPHRASE_FILE at it.
//
// Rotation caveat: --rotate-passphrase reads a "current" then a "new"
// passphrase in the same run (see cmd/sieve/main.go). Both calls consult the
// SAME env vars, so if the operator's automation sets SIEVE_PASSPHRASE_FILE
// (or _FD) for an unattended rotation, "current" and "new" resolve to the
// identical value — main.go's existing bytes.Equal(current, newPP) guard
// then correctly reports "no rotation performed" rather than silently
// rotating a passphrase onto itself. A genuinely unattended rotation to a
// DIFFERENT passphrase needs the operator's tooling to swap what the source
// points at between the two reads (or set RequireTTY on the "new" call to
// force an interactive override) — this fork does not add a second,
// distinctly-named "new passphrase" source.
func Acquire(opts PromptOptions) ([]byte, error) {
	prompt := opts.Prompt
	if prompt == "" {
		prompt = "Sieve passphrase: "
	}

	if opts.RequireTTY {
		if !IsStdinTerminal() {
			return nil, errors.New("this passphrase prompt requires a TTY: " +
				"stdin is not interactive, and RequireTTY on this call " +
				"means neither " + PassphraseFileEnv + " nor " + PassphraseFDEnv +
				" is consulted no matter what — re-run from an interactive shell.")
		}
		return acquireTTY(prompt, opts.Confirm)
	}

	if opts.Confirm {
		if path := os.Getenv(PassphraseFileEnv); path != "" {
			pp, err := acquireFile(path)
			if err != nil {
				return nil, err
			}
			log.Printf("sieve: passphrase for this confirm prompt read from %s (value never logged)", PassphraseFileEnv)
			return pp, nil
		}
		if fdStr := os.Getenv(PassphraseFDEnv); fdStr != "" {
			pp, err := acquirePassphraseFD(fdStr)
			if err != nil {
				return nil, err
			}
			log.Printf("sieve: passphrase for this confirm prompt read from %s (value never logged)", PassphraseFDEnv)
			return pp, nil
		}
		if !IsStdinTerminal() {
			return nil, errors.New("this passphrase prompt requires a TTY: " +
				"stdin is not interactive and neither " + PassphraseFileEnv +
				" nor " + PassphraseFDEnv + " is set. Re-run from an " +
				"interactive shell, or set one of those two to supply the " +
				"passphrase unattended (a single read then stands in for " +
				"both the value and its confirmation).")
		}
		return acquireTTY(prompt, true)
	}

	if path := os.Getenv(PassphraseFileEnv); path != "" {
		return acquireFile(path)
	}

	if fdStr := os.Getenv(PassphraseFDEnv); fdStr != "" {
		return acquirePassphraseFD(fdStr)
	}

	if IsStdinTerminal() {
		return acquireTTY(prompt, opts.Confirm)
	}

	return nil, errors.New("no passphrase source available: " +
		PassphraseFileEnv + " and " + PassphraseFDEnv +
		" are unset and stdin is not a TTY")
}

func acquireTTY(prompt string, confirm bool) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pp, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	if len(pp) == 0 {
		return nil, errors.New("empty passphrase")
	}

	if confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		pp2, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("read confirm: %w", err)
		}
		if !bytes.Equal(pp, pp2) {
			return nil, errors.New("passphrases do not match")
		}
		// Zero the duplicate before discarding.
		for i := range pp2 {
			pp2[i] = 0
		}
	}

	return pp, nil
}

func acquireFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read passphrase file %q: %w", path, err)
	}
	pp := bytes.TrimRight(data, "\r\n")
	if len(pp) == 0 {
		return nil, fmt.Errorf("passphrase file %q is empty", path)
	}
	return pp, nil
}

// acquirePassphraseFD reads the passphrase from the file descriptor named by
// SIEVE_PASSPHRASE_FD (e.g. "3"). Reading a descriptor as a credential is
// opt-in: the operator names the fd, so a descriptor leaked into the process
// by a launcher can't silently satisfy intake (see PassphraseFDEnv). An
// invalid fd number, a stdio fd, or a designated fd that can't be read is a
// loud error rather than a silent fallthrough.
func acquirePassphraseFD(fdStr string) ([]byte, error) {
	fd, err := strconv.Atoi(strings.TrimSpace(fdStr))
	if err != nil || fd < 0 {
		return nil, fmt.Errorf("%s=%q is not a valid file descriptor number", PassphraseFDEnv, fdStr)
	}
	if fd <= 2 {
		return nil, fmt.Errorf("%s=%d refers to stdin/stdout/stderr; designate fd 3 or higher", PassphraseFDEnv, fd)
	}
	f := os.NewFile(uintptr(fd), "passphrase-fd")
	if f == nil {
		return nil, fmt.Errorf("%s=%d is not an open file descriptor", PassphraseFDEnv, fd)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read passphrase from fd %d (%s): %w", fd, PassphraseFDEnv, err)
	}
	pp := bytes.TrimRight(data, "\r\n")
	if len(pp) == 0 {
		return nil, fmt.Errorf("fd %d (%s) supplied an empty passphrase", fd, PassphraseFDEnv)
	}
	return pp, nil
}
