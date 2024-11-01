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
	"pulsar/services"
)

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", os.Getenv("LISTEN_ADDRESS"))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	//s := grpc.NewServer()
	authorizer := services.NewAuthZService(os.Getenv("SECRET_KEY"))
	s := grpc.NewServer(grpc.UnaryInterceptor(controller.GetAuthInterceptor()))

	pb.RegisterSeccompServiceServer(s, controller.NewSeccompServiceServer(authorizer))
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

}
