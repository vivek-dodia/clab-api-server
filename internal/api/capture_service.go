package api

import (
	"context"
	"sync"

	"github.com/srl-labs/clab-api-server/internal/capture"
	"github.com/srl-labs/clab-api-server/internal/config"
)

var (
	captureManager   *capture.Manager
	captureManagerMu sync.RWMutex
)

func InitCaptureManager() {
	captureManagerMu.Lock()
	defer captureManagerMu.Unlock()

	if captureManager != nil {
		return
	}

	captureManager = capture.NewManager(capture.ManagerConfig{
		Runtime:               config.AppConfig.ClabRuntime,
		PacketflixPort:        config.AppConfig.CapturePacketflixPort,
		RemoteHostname:        config.AppConfig.CaptureRemoteHostname,
		WiresharkDockerImage:  config.AppConfig.CaptureWiresharkDockerImage,
		WiresharkPullPolicy:   config.AppConfig.CaptureWiresharkPullPolicy,
		WiresharkSessionTTL:   config.AppConfig.CaptureWiresharkSessionTTL,
		EdgesharkExtraEnvVars: config.AppConfig.CaptureEdgesharkExtraEnvVars,
	})
}

func ShutdownCaptureManager() {
	captureManagerMu.Lock()
	manager := captureManager
	captureManager = nil
	captureManagerMu.Unlock()

	if manager != nil {
		manager.Shutdown(context.Background())
	}
}

func GetCaptureManager() *capture.Manager {
	captureManagerMu.RLock()
	defer captureManagerMu.RUnlock()
	return captureManager
}
