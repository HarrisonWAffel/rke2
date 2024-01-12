//go:build windows
// +build windows

package windows

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/k3s-io/k3s/pkg/version"
	"github.com/pkg/errors"
	"github.com/rancher/wins/pkg/logs"
	"github.com/rancher/wins/pkg/profilings"
	"github.com/rancher/wrangler/pkg/signals"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

type service struct{}

var Service = &service{}

func (h *service) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	statuses <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range requests {
		switch c.Cmd {
		case svc.Cmd(windows.SERVICE_CONTROL_PARAMCHANGE):
			statuses <- c.CurrentStatus
		case svc.Interrogate:
			statuses <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			statuses <- svc.Status{State: svc.StopPending}
			if !signals.RequestShutdown() {
				logrus.Infof("Windows Service is shutting down")
				statuses <- svc.Status{State: svc.Stopped}
				os.Exit(0)
			}

			logrus.Infof("Windows Service is shutting down gracefully")
			statuses <- svc.Status{State: svc.StopPending}
			statuses <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
	return false, 0
}

func StartService() (bool, error) {
	if ok, err := svc.IsWindowsService(); err != nil || !ok {
		return ok, err
	}

	// ETW tracing
	etw, err := logs.NewEtwProviderHook(version.Program)
	if err != nil {
		return false, errors.Wrap(err, "could not create ETW provider logrus hook")
	}
	logrus.AddHook(etw)

	el, err := logs.NewEventLogHook(version.Program)
	if err != nil {
		return false, errors.Wrap(err, "could not create eventlog logrus hook")
	}
	logrus.AddHook(el)

	// Creates a Win32 event defined on a Global scope at stackdump-{pid} that can be signaled by
	// built-in administrators of the Windows machine or by the local system.
	// If this Win32 event (Global//stackdump-{pid}) is signaled, a goroutine launched by this call
	// will dump the current stack trace into {windowsTemporaryDirectory}/{default.WindowsServiceName}.{pid}.stack.logs
	profilings.SetupDumpStacks(version.Program, os.Getpid())

	go func() {
		if err := svc.Run(version.Program, Service); err != nil {
			logrus.Fatalf("Windows Service error, exiting: %s", err)
		}
	}()

	return true, nil
}

// MonitorProcessExit ensures that the kubelet, kube-proxy, calico-node, and containerd processes have stopped running.
func MonitorProcessExit() error {
	processMonitorCtx, done := context.WithDeadline(context.Background(), time.Now().Add(time.Second*10))
	defer done()

	pwsh := `
 	$ErrorActionPreference = "SilentlyContinue"
	while(1) {
		$successfulExit = $true
		foreach ($process in @("kubelet","kube-proxy","calico-node","containerd"))
		{
			if (Get-Process -Name $process) {
				$successfulExit = $false
				break
			}
		}
		if ($successfulExit) {
			exit 0
		}
		sleep 1
	}
`

	logrus.Infof("Waiting for all processes to exit...")

	cmd := exec.CommandContext(processMonitorCtx, "powershell", pwsh)
	o, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to ensure all processes have exited: %s: %w", string(o), err)
	}

	return nil
}
