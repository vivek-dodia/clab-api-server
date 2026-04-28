package config

import (
	"os"
	"testing"

	"github.com/spf13/viper"
)

func TestLoadConfigDefaultsEnableTLSAutoCert(t *testing.T) {
	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWd)
		viper.Reset()
	})

	viper.Reset()
	if err := LoadConfig(".env"); err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if AppConfig.APIPort != "8090" {
		t.Fatalf("expected API_PORT default to be 8090, got %q", AppConfig.APIPort)
	}
	if !AppConfig.TLSEnable {
		t.Fatal("expected TLS_ENABLE default to be true")
	}
	if !AppConfig.TLSAutoCert {
		t.Fatal("expected TLS_AUTO_CERT default to be true")
	}
}
