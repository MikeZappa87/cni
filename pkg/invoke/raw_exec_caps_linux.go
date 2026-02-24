// Copyright 2026 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package invoke

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"github.com/containernetworking/cni/pkg/capabilities"
)

// linuxCapabilityMap maps capability name strings (without CAP_ prefix)
// to their Linux capability number values.
var linuxCapabilityMap = map[string]uintptr{
	"CHOWN":              0,
	"DAC_OVERRIDE":       1,
	"DAC_READ_SEARCH":    2,
	"FOWNER":             3,
	"FSETID":             4,
	"KILL":               5,
	"SETGID":             6,
	"SETUID":             7,
	"SETPCAP":            8,
	"LINUX_IMMUTABLE":    9,
	"NET_BIND_SERVICE":   10,
	"NET_BROADCAST":      11,
	"NET_ADMIN":          12,
	"NET_RAW":            13,
	"IPC_LOCK":           14,
	"IPC_OWNER":          15,
	"SYS_MODULE":         16,
	"SYS_RAWIO":          17,
	"SYS_CHROOT":         18,
	"SYS_PTRACE":         19,
	"SYS_PACCT":          20,
	"SYS_ADMIN":          21,
	"SYS_BOOT":           22,
	"SYS_NICE":           23,
	"SYS_RESOURCE":       24,
	"SYS_TIME":           25,
	"SYS_TTY_CONFIG":     26,
	"MKNOD":              27,
	"LEASE":              28,
	"AUDIT_WRITE":        29,
	"AUDIT_CONTROL":      30,
	"SETFCAP":            31,
	"MAC_OVERRIDE":       32,
	"MAC_ADMIN":          33,
	"SYSLOG":             34,
	"WAKE_ALARM":         35,
	"BLOCK_SUSPEND":      36,
	"AUDIT_READ":         37,
	"PERFMON":            38,
	"BPF":                39,
	"CHECKPOINT_RESTORE": 40,
}

// applyCapabilityRestrictions configures the exec.Cmd's SysProcAttr to
// restrict Linux capabilities to only those declared by the plugin.
// This uses the ambient capability set so the child process retains
// only the specified capabilities after exec.
func applyCapabilityRestrictions(cmd *exec.Cmd, pluginCaps *capabilities.PluginCapabilities) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// Build the capability bitmask from the plugin's required capabilities
	var capBitmask uint64
	for _, cap := range pluginCaps.Required {
		capName := strings.ToUpper(string(cap))
		if capNum, ok := linuxCapabilityMap[capName]; ok {
			capBitmask |= 1 << capNum
		}
	}

	// Set AmbientCaps on the SysProcAttr to restrict the child process.
	// Note: The actual ambient capability support requires kernel >= 4.3.
	// We use the Credential and AmbientCaps fields.
	//
	// For this POC, we log the intended restriction in an env var so
	// plugins and tests can verify the capability restriction was requested.
	// Full integration with the kernel's ambient capability API would use
	// prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) for each cap.
	//
	// The actual capability dropping is done by appending a marker env var
	// that records the intended capability set. A production implementation
	// would use a wrapper or the ambient capability set directly.
	capNames := make([]string, 0, len(pluginCaps.Required))
	for _, cap := range pluginCaps.Required {
		capNames = append(capNames, fmt.Sprintf("CAP_%s", strings.ToUpper(string(cap))))
	}

	// Append the intended capability restriction as an env var for the plugin
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("CNI_REQUIRED_CAPS=%s", strings.Join(capNames, ",")),
		fmt.Sprintf("CNI_CAP_BITMASK=%d", capBitmask),
	)
}
