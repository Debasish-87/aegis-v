package orchestrator

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

func ProvisionContainer(imageName string, serviceName string) error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("Docker client error: %v", err)
	}
	defer cli.Close()

	fmt.Printf("[WORKER] Cleaning up: %s\n", serviceName)
	cli.ContainerRemove(ctx, serviceName, types.ContainerRemoveOptions{Force: true})

	fmt.Printf("[WORKER] Pulling: %s\n", imageName)
	out, err := cli.ImagePull(ctx, imageName, types.ImagePullOptions{})
	if err != nil {
		return err
	}
	defer out.Close()
	io.Copy(os.Stdout, out)

	hostBinding := nat.PortBinding{HostIP: "0.0.0.0", HostPort: "8081"}
	containerPort, _ := nat.NewPort("tcp", "80")

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: imageName,
	}, &container.HostConfig{
		PortBindings: nat.PortMap{containerPort: []nat.PortBinding{hostBinding}},
		AutoRemove:   false, 
	}, nil, nil, serviceName)

	if err != nil {
		return err
	}

	return cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{})
}

func IsContainerRunning(serviceName string) bool {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return false
	}
	defer cli.Close()

	container, err := cli.ContainerInspect(ctx, serviceName)
	if err != nil {
		return false
	}
	return container.State.Running
}