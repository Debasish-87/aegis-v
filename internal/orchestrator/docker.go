package orchestrator

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

// getDockerClient: Strict versioning for compatibility with your local system
func getDockerClient() (*client.Client, error) {
	return client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
		client.WithVersion("1.44"),
	)
}

// GetAllContainers: (NEW) Informs the Engine about all running services
// This will populate the 'SERVICE NAME' and 'DOCKER IMAGE' columns in aegis-ctl
func GetAllContainers() ([]types.Container, error) {
	cli, err := getDockerClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	// Fetch all containers (running + stopped) to show full cluster state
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{All: true})
	if err != nil {
		return nil, err
	}
	return containers, nil
}

// GetContainerNameByNamespace: maps eBPF MntNS to a human-readable Docker Name
func GetContainerNameByNamespace(mntNs uint32) string {
	// Bypass host/system namespaces
	if mntNs == 0 || mntNs == 4026531832 || mntNs == 4026531840 {
		return "" 
	}

	files, err := os.ReadDir("/proc")
	if err != nil {
		return "UNKNOWN"
	}

	for _, f := range files {
		if !f.IsDir() {
			continue
		}
		
		pid := f.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}

		nsPath := filepath.Join("/proc", pid, "ns", "mnt")
		target, err := os.Readlink(nsPath)
		if err != nil {
			continue
		}

		// Check if this process belongs to the targeted Namespace
		if strings.Contains(target, strconv.FormatUint(uint64(mntNs), 10)) {
			cgroupPath := filepath.Join("/proc", pid, "cgroup")
			data, err := os.ReadFile(cgroupPath)
			if err != nil {
				continue
			}

			// Robust extraction of 64-char Docker ID from cgroup
			containerID := extractIDFromCgroup(string(data))
			if containerID != "" {
				// We only need the first 12 chars for resolveContainerName
				return resolveContainerName(containerID[:12])
			}
		}
	}
	return ""
}

// extractIDFromCgroup: Helper to find the actual container ID in messy cgroup strings
func extractIDFromCgroup(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.Contains(line, "docker") {
			parts := strings.Split(line, "/")
			for _, part := range parts {
				// Docker IDs are exactly 64 characters
				cleanPart := strings.TrimSuffix(part, ".scope")
				cleanPart = strings.TrimPrefix(cleanPart, "docker-")
				if len(cleanPart) == 64 {
					return cleanPart
				}
			}
		}
	}
	return ""
}

func resolveContainerName(shortID string) string {
	cli, err := getDockerClient()
	if err != nil {
		return shortID
	}
	defer cli.Close()

	inspect, err := cli.ContainerInspect(context.Background(), shortID)
	if err != nil {
		return shortID
	}
	// Return the name without the leading slash
	return strings.TrimPrefix(inspect.Name, "/")
}

// ProvisionContainer: Deployment logic for launching new services
func ProvisionContainer(imageName string, serviceName string, cpu float64, mem int64) error {
	ctx := context.Background()
	cli, err := getDockerClient()
	if err != nil {
		return fmt.Errorf("Docker client setup error: %v", err)
	}
	defer cli.Close()

	fmt.Printf("[ORCHESTRATOR] 🚀 Provisioning %s...\n", serviceName)

	// Remove old instance if exists
	_ = cli.ContainerRemove(ctx, serviceName, types.ContainerRemoveOptions{Force: true})

	// Pull image
	fmt.Printf("[ORCHESTRATOR] Pulling image: %s\n", imageName)
	reader, err := cli.ImagePull(ctx, imageName, types.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("Pull failed: %v", err)
	}
	defer reader.Close()
	_, _ = io.Copy(io.Discard, reader) // Discard output to keep engine logs clean

	// Resource limits & Ports
	hostBinding := nat.PortBinding{HostIP: "0.0.0.0", HostPort: "8081"}
	containerPort, _ := nat.NewPort("tcp", "80")

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: imageName,
	}, &container.HostConfig{
		PortBindings: nat.PortMap{containerPort: []nat.PortBinding{hostBinding}},
		Resources: container.Resources{
			NanoCPUs: int64(cpu * 1e9),
			Memory:   mem * 1024 * 1024,
		},
	}, nil, nil, serviceName)

	if err != nil {
		return fmt.Errorf("Create failed: %v", err)
	}

	return cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{})
}

func IsContainerRunning(serviceName string) bool {
	cli, err := getDockerClient()
	if err != nil {
		return false
	}
	defer cli.Close()
	inspect, err := cli.ContainerInspect(context.Background(), serviceName)
	if err != nil {
		return false
	}
	return inspect.State.Running
}

func StopContainer(serviceName string) error {
	cli, err := getDockerClient()
	if err != nil {
		return err
	}
	defer cli.Close()
	timeout := 5
	_ = cli.ContainerStop(context.Background(), serviceName, container.StopOptions{Timeout: &timeout})
	return cli.ContainerRemove(context.Background(), serviceName, types.ContainerRemoveOptions{Force: true})
}