package capabilities

import (
	"testing"
)

func TestNeedsFullRoot(t *testing.T) {
	tests := []struct {
		name     string
		pc       PluginCapabilities
		expected bool
	}{
		{
			name:     "empty requires full root",
			pc:       PluginCapabilities{},
			expected: true,
		},
		{
			name:     "nil required requires full root",
			pc:       PluginCapabilities{Required: nil},
			expected: true,
		},
		{
			name:     "with caps does not need full root",
			pc:       PluginCapabilities{Required: []LinuxCapability{NetAdmin}},
			expected: false,
		},
		{
			name:     "with socket does not need full root",
			pc:       PluginCapabilities{NeedsRuntimeSocket: true},
			expected: false,
		},
		{
			name: "empty required with socket does not need full root",
			pc: PluginCapabilities{
				Required:           []LinuxCapability{},
				NeedsRuntimeSocket: true,
			},
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pc.NeedsFullRoot(); got != tt.expected {
				t.Errorf("NeedsFullRoot() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHasCapability(t *testing.T) {
	pc := PluginCapabilities{Required: []LinuxCapability{NetAdmin, NetRaw}}

	if !pc.HasCapability(NetAdmin) {
		t.Error("expected HasCapability(NetAdmin) to be true")
	}
	if !pc.HasCapability(NetRaw) {
		t.Error("expected HasCapability(NetRaw) to be true")
	}
	if pc.HasCapability(SysAdmin) {
		t.Error("expected HasCapability(SysAdmin) to be false")
	}
}

func TestValidate(t *testing.T) {
	valid := PluginCapabilities{Required: []LinuxCapability{NetAdmin, NetRaw, SysAdmin}}
	if err := valid.Validate(); err != nil {
		t.Errorf("expected no error for valid caps, got %v", err)
	}

	invalid := PluginCapabilities{Required: []LinuxCapability{"TOTALLY_FAKE"}}
	if err := invalid.Validate(); err == nil {
		t.Error("expected error for unknown capability")
	}

	empty := PluginCapabilities{}
	if err := empty.Validate(); err != nil {
		t.Errorf("expected no error for empty caps, got %v", err)
	}
}

func TestParseFromConfig(t *testing.T) {
	t.Run("with required capabilities", func(t *testing.T) {
		cfg := []byte(`{"type":"bridge","requiredCapabilities":["NET_ADMIN","NET_RAW"]}`)
		pc, err := ParseFromConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(pc.Required) != 2 {
			t.Errorf("expected 2 required, got %d", len(pc.Required))
		}
		if pc.NeedsFullRoot() {
			t.Error("expected NeedsFullRoot() to be false")
		}
	})

	t.Run("traditional config without capability fields", func(t *testing.T) {
		cfg := []byte(`{"type":"bridge"}`)
		pc, err := ParseFromConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !pc.NeedsFullRoot() {
			t.Error("expected NeedsFullRoot() to be true for traditional config")
		}
	})

	t.Run("with runtimeSocket", func(t *testing.T) {
		cfg := []byte(`{"type":"bridge","requiredCapabilities":[],"runtimeSocket":true}`)
		pc, err := ParseFromConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pc.NeedsFullRoot() {
			t.Error("expected NeedsFullRoot() to be false with runtimeSocket")
		}
		if !pc.NeedsRuntimeSocket {
			t.Error("expected NeedsRuntimeSocket to be true")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		cfg := []byte(`{invalid}`)
		_, err := ParseFromConfig(cfg)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

func TestCapabilityNames(t *testing.T) {
	pc := PluginCapabilities{Required: []LinuxCapability{NetAdmin, NetRaw}}
	names := pc.CapabilityNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %d", len(names))
	}
	if names[0] != "CAP_NET_ADMIN" {
		t.Errorf("expected CAP_NET_ADMIN, got %s", names[0])
	}
	if names[1] != "CAP_NET_RAW" {
		t.Errorf("expected CAP_NET_RAW, got %s", names[1])
	}
}
