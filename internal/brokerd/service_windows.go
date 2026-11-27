package brokerd

import (
	"context"
	"time"

	"golang.org/x/sys/windows/svc"
)

// IsWindowsService reports whether the process was started by the service
// control manager.
func IsWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// RunService runs fn as the Windows service name. fn's context ends when the
// service control manager asks the service to stop.
func RunService(name string, fn func(ctx context.Context) error) error {
	return svc.Run(name, &serviceHandler{run: fn})
}

type serviceHandler struct{ run func(context.Context) error }

// stopGrace bounds how long a stop request waits for the daemon to wind down.
const stopGrace = 20 * time.Second

func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(stopGrace):
				}
				return false, 0
			}
		case err := <-done:
			if err != nil {
				return true, 1
			}
			return false, 0
		}
	}
}
