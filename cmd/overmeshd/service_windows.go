//go:build windows

package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "OverMesh"

// serviceCommand implements -service install|uninstall|start|stop.
func serviceCommand(cmd string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()

	switch cmd {
	case "install":
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if s, err := m.OpenService(serviceName); err == nil {
			s.Close()
			return fmt.Errorf("service %s already installed", serviceName)
		}
		s, err := m.CreateService(serviceName, exe, mgr.Config{
			DisplayName: "OverMesh node daemon",
			Description: "Self-hosted WireGuard mesh VPN node (overmeshd)",
			StartType:   mgr.StartAutomatic,
		})
		if err != nil {
			return err
		}
		defer s.Close()
		fmt.Printf("service %s installed; start it with: overmeshd -service start\n", serviceName)
		return nil
	case "uninstall":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return fmt.Errorf("service not installed: %w", err)
		}
		defer s.Close()
		_, _ = s.Control(svc.Stop)
		return s.Delete()
	case "start":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return fmt.Errorf("service not installed: %w", err)
		}
		defer s.Close()
		return s.Start()
	case "stop":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return fmt.Errorf("service not installed: %w", err)
		}
		defer s.Close()
		status, err := s.Control(svc.Stop)
		if err != nil {
			return err
		}
		for i := 0; i < 20 && status.State != svc.Stopped; i++ {
			time.Sleep(300 * time.Millisecond)
			status, err = s.Query()
			if err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown -service command %q (install|uninstall|start|stop)", cmd)
	}
}

type omService struct {
	start func()
	stop  func()
}

func (s *omService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	go s.start()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			s.stop()
			return false, 0
		}
	}
	return false, 0
}

// runAsServiceIfNeeded runs the daemon under the service control
// manager when launched by it; returns false for a normal console run.
func runAsServiceIfNeeded(start, stop func()) bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return false
	}
	_ = svc.Run(serviceName, &omService{start: start, stop: stop})
	return true
}
