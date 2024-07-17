// server/main.go
package main

import (
	"flag"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	"pulsar/controller"
	pb "pulsar/model/protobuf"
)

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", os.Getenv("LISTEN_ADDRESS"))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterSeccompServiceServer(s, &controller.Server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

}
