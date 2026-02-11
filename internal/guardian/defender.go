package guardian

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// List of process names and substrings that should NEVER be killed
var protectedProcesses = []string{
	"aegis-engine",
	"aegis-ctl",
	"aegis-viz",
	"systemd",
	"dockerd",
	"containerd",
	"fuser", // 👈 Add this
    "lsof",
	"sshd",
	"go",
	"sudo",
}

// KillProcess sends a SIGKILL signal with Parent-Aware Safety logic
func KillProcess(pid int, comm string) error {
	selfPid := os.Getpid()

	// 1. Basic Safety: System critical processes (PID 1 is init/systemd)
	if pid <= 100 {
		return fmt.Errorf("safety check: skipping system process %d (%s)", pid, comm)
	}

	// 2. Self-Protection: Don't kill the engine itself
	if pid == selfPid {
		return fmt.Errorf("self-protection: prevented engine suicide")
	}

	// 3. Command Whitelist Check: (Case-insensitive)
	cleanComm := strings.ToLower(comm)
	for _, protected := range protectedProcesses {
		if strings.Contains(cleanComm, protected) {
			return fmt.Errorf("policy protection: %s is whitelisted", comm)
		}
	}

	// 4. PPID Context Check (The Fix for 'Killed' status)
	// Agar is process ka Parent hamara Engine hai, toh ye valid request ho sakti hai
	ppid := getParentPid(pid)
	if ppid == selfPid {
		return fmt.Errorf("context check: skipping child process of engine")
	}

	// 5. Execute Kill
	err := syscall.Kill(pid, syscall.SIGKILL)
	if err != nil {
		if err == syscall.ESRCH {
			return fmt.Errorf("process %d already exited", pid)
		}
		return fmt.Errorf("failed to kill %d: %v", pid, err)
	}

	// 6. Styled Success Output
	fmt.Printf("\n\033[31m[DEFENDER] 🛡️ ALERT: Suspicious process '%s' (PID: %d) TERMINATED.\033[0m\n", comm, pid)
	fmt.Printf("\033[32m   └─ [REASON]: Unauthorized sensitive execution in shielded zone.\033[0m\n")

	return nil
}

// Helper function to find Parent PID from /proc
func getParentPid(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	// /proc/[pid]/stat format: pid (comm) state ppid ...
	var ppid int
	fmt.Sscanf(string(data), "%d %*s %*s %d", &ppid, &ppid)
	return ppid
}