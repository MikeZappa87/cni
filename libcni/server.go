package libcni

import (
	"net"
	"os"

	cni "github.com/containernetworking/cni/pkg/grpc"
	"google.golang.org/grpc"
)

func NewCNIServer(sockAddr string, srv cni.CNIServer) error {
	if _, err := os.Stat(sockAddr); !os.IsNotExist(err) {
		if err := os.RemoveAll(sockAddr); err != nil {
			return err
		}
	}

	listener, err := net.Listen("unix", sockAddr)
	if err != nil {
		return err
	}

	server := grpc.NewServer()

	cni.RegisterCNIServer(server, srv)
	
	return server.Serve(listener)
}