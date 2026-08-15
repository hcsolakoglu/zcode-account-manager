package zcode

import (
	"context"
	"os"

	proc "github.com/hcsolakoglu/zcode-auth/internal/process"
)

// Process aliases keep ZCode command code independent from the generic proc
// package while preserving PID/start-time identity for safe signaling.
type Process = proc.Info
type StopOptions = proc.StopOptions
type StartOptions = proc.StartOptions

// DetectProcesses finds exact ZCode executable matches.  It cannot match a
// similarly named zcode-cli because detection is based on /proc/exe identity.
func DetectProcesses(paths Paths) ([]Process, error) {
	return proc.List(paths.Executable)
}

// StopProcess requests graceful SIGTERM and bounded waiting, escalating only
// when options.Force is explicitly true.
func StopProcess(ctx context.Context, paths Paths, process Process, options StopOptions) error {
	return proc.Stop(ctx, process, paths.Executable, options)
}

// StartProcess starts ZCode directly without a shell.
func StartProcess(paths Paths, options StartOptions) (*os.Process, error) {
	return proc.Start(paths.Executable, options)
}

// DetectVersion reads static package metadata first and only executes a probe
// when the caller explicitly allows it.
func DetectVersion(ctx context.Context, paths Paths, options proc.VersionOptions) (string, error) {
	return proc.DetectVersion(ctx, paths.Executable, options)
}
