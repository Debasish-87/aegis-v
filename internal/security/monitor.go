package security

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Debasish-87/aegis-v/internal/guardian"
	"github.com/Debasish-87/aegis-v/internal/orchestrator"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bpf guardian.c

type Event struct {
	Pid   uint32
	Ppid  uint32
	Uid   uint32
	MntNs uint32
	Comm  [16]byte
}

func StartSecurityMonitor() {
	selfPid := uint32(os.Getpid())

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("[CRITICAL] Failed to remove memlock limit: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Printf("[ERROR] Failed to load eBPF objects: %v", err)
		return
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		log.Printf("[ERROR] Failed to attach tracepoint: %v", err)
		objs.Close()
		return
	}

	log.Println("[GUARDIAN] 🛡️ Advanced eBPF Security Probe Active. Monitoring Namespaces...")

	rd, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		log.Printf("[ERROR] Failed to open ringbuf reader: %v", err)
		tp.Close()
		objs.Close()
		return
	}

	go func() {
		defer tp.Close()
		defer objs.Close()
		defer rd.Close()

		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}

			var event Event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}

			// --- FILTER 1: Self & Engine Direct Child Check ---
			if event.Pid == selfPid || event.Ppid == selfPid {
				continue
			}

			comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

			// --- FILTER 2: DEEP LINEAGE & WHITELIST ---
			// Added isTrustedPath for binary-level verification
			if isWhitelisted(comm) || isAncestorWhitelisted(event.Ppid) || isTrustedPath(event.Pid, event.Ppid) {
				continue
			}

			// --- FILTER 3: Noise signals ---
			if isNoise(comm) {
				continue
			}

			containerName := orchestrator.GetContainerNameByNamespace(event.MntNs)
			if isContainerStartup(comm) {
				continue
			}

			// --- FILTER 4: Smart Shell Detection ---
			if (comm == "sh" || comm == "bash" || comm == "dash") {
				if !isInteractiveShellAttempt(event.Pid) {
					continue
				}
			}

			// CLEAN SOURCE TAGGING FOR DATABASE
			sourceTag := "HOST / SYSTEM"
			if containerName != "" {
				sourceTag = containerName 
			} else if event.MntNs != 4026531840 && event.MntNs != 0 {
				sourceTag = fmt.Sprintf("NS:%d", event.MntNs)
			}

			userTag := "USER"
			riskLevel := "MEDIUM"
			alertEmoji := "🚨"

			if event.Uid == 0 {
				userTag = "ROOT ⚠️"
				riskLevel = "HIGH / CRITICAL"
			}

			// --- THE CORE LOGIC ---
			if isSensitive(comm) {
				if isSystemBackground(event.Pid, event.Ppid) {
					continue
				}

				riskLevel = "SENSITIVE ACTIVITY 🚩"
				alertEmoji = "🚩"

				fmt.Printf("\n[EBPF ALERT] %s Unauthorized Exec Detected!\n", alertEmoji)
				fmt.Printf("   ├─ Command:    %s\n", comm)
				fmt.Printf("   ├─ Risk:       %s\n", riskLevel)
				fmt.Printf("   ├─ Source:     %s\n", sourceTag)
				fmt.Printf("   ├─ Identity:   %s\n", userTag)
				fmt.Printf("   └─ PID:        %d (Parent: %d)\n", event.Pid, event.Ppid)
				fmt.Printf("--------------------------------------------\n")

				// Log to Database via Guardian
				guardian.ProcessAndLog(comm, int(event.Pid), riskLevel, sourceTag, userTag)

				// Active Defense: Kill the suspicious process
				err := guardian.KillProcess(int(event.Pid), comm)
				if err == nil {
					fmt.Printf("   └─ [DEFENDER]: PID %d Neutralized. 🛡️\n", event.Pid)
				}
			}
		}
	}()
}

// isTrustedPath checks the actual binary location on disk via symlink
func isTrustedPath(pid, ppid uint32) bool {
	for _, id := range []uint32{pid, ppid} {
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", id))
		if err == nil {
			// Trust any execution coming from the Aegis-V project binaries
			if strings.Contains(exe, "aegis-ctl") || strings.Contains(exe, "aegis-engine") {
				return true
			}
		}
	}
	return false
}

func isInteractiveShellAttempt(pid uint32) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	// cmdline arguments are null-separated
	args := bytes.Split(data, []byte{0})
	
	// If it's a shell running a specific command (like sh -c), ignore it
	if len(args) > 2 && len(args[1]) > 0 {
		return false
	}

	// If it's a naked shell, check if it's attached to a terminal (TTY)
	return hasTTY(pid)
}

func hasTTY(pid uint32) bool {
	fd0, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/0", pid))
	if err != nil {
		return false
	}
	// pts = Pseudo Terminal Slave (interactive terminal)
	return strings.Contains(fd0, "/dev/pts/") || strings.Contains(fd0, "/dev/tty")
}

func isAncestorWhitelisted(ppid uint32) bool {
	currPpid := ppid
	for i := 0; i < 6; i++ { 
		if currPpid <= 1 { break }
		
		// 1. Binary path check (Strongest)
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", currPpid))
		if err == nil && (strings.Contains(exe, "aegis-ctl") || strings.Contains(exe, "aegis-engine")) {
			return true
		}

		// 2. Command name check
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", currPpid))
		if err == nil && isWhitelisted(strings.TrimSpace(string(data))) {
			return true
		}

		// Get parent of parent
		statData, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", currPpid))
		if err != nil { break }
		fmt.Sscanf(string(statData), "%d %*s %*s %d", &currPpid, &currPpid)
	}
	return false
}

func isSystemBackground(pid, ppid uint32) bool {
	return isWhitelisted(fmt.Sprintf("%d", ppid))
}

func isWhitelisted(comm string) bool {
	safeTools := []string{
		"aegis-ctl", "aegis-engine", "docker", "dockerd",
		"containerd", "runc", "containerd-shim", "sudo",
		"gnome-shell", "gnome-terminal", "tmux", "sshd",
		"systemd", "dbus-daemon", "go", "build",
	}
	for _, tool := range safeTools {
		if comm == tool || strings.Contains(comm, tool) {
			return true
		}
	}
	return false
}

func isNoise(comm string) bool {
	noiseSignals := []string{
		"code", "gopls", "cpuUsage", "pg_isready", "lesspipe",
		"cron", "apt-check", "update-notifier", "nice", "ionice",
		"node", "npm", "sa1", "ls", "ps", "grep",
	}
	for _, signal := range noiseSignals {
		if strings.Contains(comm, signal) {
			return true
		}
	}
	return false
}

func isContainerStartup(comm string) bool {
	startups := []string{"docker-entrypoi", "spawn", "apt-daily"}
	for _, s := range startups {
		if strings.Contains(comm, s) {
			return true
		}
	}
	return false
}

func isSensitive(comm string) bool {
	tools := []string{"sh", "bash", "dash", "curl", "wget", "nc", "netcat", "whoami", "cat"}
	for _, tool := range tools {
		if comm == tool {
			return true
		}
	}
	return false
}