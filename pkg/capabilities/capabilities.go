package capabilities

import (
	"encoding/json"
	"fmt"
	"strings"
)

// LinuxCapability represents a Linux capability without the CAP_ prefix.
type LinuxCapability string

const (
	NetAdmin       LinuxCapability = "NET_ADMIN"
	NetRaw         LinuxCapability = "NET_RAW"
	SysAdmin       LinuxCapability = "SYS_ADMIN"
	DacOverride    LinuxCapability = "DAC_OVERRIDE"
	DacReadSearch  LinuxCapability = "DAC_READ_SEARCH"
	NetBindService LinuxCapability = "NET_BIND_SERVICE"
	SysPtrace      LinuxCapability = "SYS_PTRACE"
)

// AllKnownCapabilities is the set of all recognized Linux capabilities.
var AllKnownCapabilities = map[LinuxCapability]bool{
	NetAdmin:                              true,
	NetRaw:                                true,
	SysAdmin:                              true,
	DacOverride:                           true,
	DacReadSearch:                         true,
	NetBindService:                        true,
	SysPtrace:                             true,
	LinuxCapability("AUDIT_CONTROL"):      true,
	LinuxCapability("AUDIT_READ"):         true,
	LinuxCapability("AUDIT_WRITE"):        true,
	LinuxCapability("BLOCK_SUSPEND"):      true,
	LinuxCapability("BPF"):                true,
	LinuxCapability("CHECKPOINT_RESTORE"): true,
	LinuxCapability("CHOWN"):              true,
	LinuxCapability("FOWNER"):             true,
	LinuxCapability("FSETID"):             true,
	LinuxCapability("IPC_LOCK"):           true,
	LinuxCapability("IPC_OWNER"):          true,
	LinuxCapability("KILL"):               true,
	LinuxCapability("LEASE"):              true,
	LinuxCapability("LINUX_IMMUTABLE"):    true,
	LinuxCapability("MAC_ADMIN"):          true,
	LinuxCapability("MAC_OVERRIDE"):       true,
	LinuxCapability("MKNOD"):              true,
	LinuxCapability("NET_BROADCAST"):      true,
	LinuxCapability("PERFMON"):            true,
	LinuxCapability("SETFCAP"):            true,
	LinuxCapability("SETGID"):             true,
	LinuxCapability("SETPCAP"):            true,
	LinuxCapability("SETUID"):             true,
	LinuxCapability("SYS_BOOT"):           true,
	LinuxCapability("SYS_CHROOT"):         true,
	LinuxCapability("SYS_MODULE"):         true,
	LinuxCapability("SYS_NICE"):           true,
	LinuxCapability("SYS_PACCT"):          true,
	LinuxCapability("SYS_RAWIO"):          true,
	LinuxCapability("SYS_RESOURCE"):       true,
	LinuxCapability("SYS_TIME"):           true,
	LinuxCapability("SYS_TTY_CONFIG"):     true,
	LinuxCapability("SYSLOG"):             true,
	LinuxCapability("WAKE_ALARM"):         true,
}

// PluginCapabilities represents the capability requirements for a CNI plugin.
type PluginCapabilities struct {
	// Required is the set of Linux capabilities the plugin needs.
	// If nil or empty, the plugin requires full root (backwards-compat).
	Required []LinuxCapability `json:"requiredCapabilities,omitempty"`

	// NeedsRuntimeSocket indicates the plugin wants a gRPC socket
	// back to the runtime for delegating privileged operations.
	NeedsRuntimeSocket bool `json:"runtimeSocket,omitempty"`
}

// NeedsFullRoot returns true if the plugin has not declared specific
// capability requirements and thus needs full root privileges.
func (pc *PluginCapabilities) NeedsFullRoot() bool {
	return len(pc.Required) == 0 && !pc.NeedsRuntimeSocket
}

// HasCapability checks whether the plugin requires a specific capability.
func (pc *PluginCapabilities) HasCapability(cap LinuxCapability) bool {
	for _, c := range pc.Required {
		if c == cap {
			return true
		}
	}
	return false
}

// Validate checks that all declared capabilities are recognized.
func (pc *PluginCapabilities) Validate() error {
	for _, cap := range pc.Required {
		normalized := LinuxCapability(strings.ToUpper(string(cap)))
		if !AllKnownCapabilities[normalized] {
			return fmt.Errorf("unknown Linux capability: %q", cap)
		}
	}
	return nil
}

// ParseFromConfig extracts PluginCapabilities from raw plugin config JSON.
func ParseFromConfig(configBytes []byte) (*PluginCapabilities, error) {
	pc := &PluginCapabilities{}
	if err := json.Unmarshal(configBytes, pc); err != nil {
		return nil, fmt.Errorf("failed to parse plugin capabilities: %w", err)
	}
	return pc, nil
}

// CapabilityNames returns capability names as strings with CAP_ prefix.
func (pc *PluginCapabilities) CapabilityNames() []string {
	names := make([]string, len(pc.Required))
	for i, cap := range pc.Required {
		names[i] = "CAP_" + strings.ToUpper(string(cap))
	}
	return names
}
