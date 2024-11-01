package controller

import (
	"context"
	"log"
	pb "pulsar/model/protobuf"
	repo "pulsar/repository"
	"pulsar/services"
	util "pulsar/util"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Server struct {
	pb.UnimplementedSeccompServiceServer
	authorizer services.AuthZService
}

func NewSeccompServiceServer(authorizer services.AuthZService) pb.SeccompServiceServer {
	return &Server{
		authorizer: authorizer,
	}
}

func (s *Server) DefineSeccompProfile(ctx context.Context, in *pb.SeccompProfileDefinitionRequest) (*pb.BasicResponse, error) {
	log.Printf("Received: %v", in.GetProfile().GetNamespace())
	err := s.authorizer.Authorize(ctx, "org.namespace.add", "org", util.GetOrgIdFromNamespace(in.Profile.Namespace))
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, err.Error())
	}
	if err := util.ValidateDefineSeccompProfileRequest(in); err != nil {
		return nil, err
	}
	repo.CreateSeccompProfile(in)
	return &pb.BasicResponse{Success: true, Message: "Your profile has been successfully created"}, nil
}

// todo da li se kreiraju svi profili za isti ns?
func (s *Server) DefineSeccompProfileBatch(ctx context.Context, in *pb.BatchSeccompProfileDefinitionRequest) (*pb.BasicResponse, error) {
	for _, profile := range in.Profiles {
		if err := util.ValidateDefineSeccompProfileRequest(profile); err != nil {
			return nil, err
		}
	}
	for _, profile := range in.Profiles {
		repo.CreateSeccompProfile(profile)
	}
	return &pb.BasicResponse{Message: "Batch completed. Profiles successfully created"}, nil

}

func (s *Server) GetSeccompProfile(ctx context.Context, in *pb.SeccompProfile) (*pb.GetSeccompProfileResponse, error) {
	log.Printf("Requesting Seccomp Profile")
	err := s.authorizer.Authorize(ctx, "org.namespace.add", "org", util.GetOrgIdFromNamespace(in.Namespace))
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, err.Error())
	}

	if err := util.ValidateGetSeccompProfileRequest(in); err != nil {
		return nil, err
	}
	jsonProfile, e := repo.GetSeccompProfile(in)
	if e != nil {
		return nil, e
	}
	syscalls := make([]*pb.Syscalls, 0)
	for _, syscall := range jsonProfile.Definition.Syscalls {
		syscalls = append(syscalls, &pb.Syscalls{Names: syscall.Names, Action: syscall.Action})
	}
	return &pb.GetSeccompProfileResponse{
		Profile: &pb.SeccompProfile{
			Namespace:    jsonProfile.Profile.Namespace,
			Application:  jsonProfile.Profile.Application,
			Name:         jsonProfile.Profile.Name,
			Version:      jsonProfile.Profile.Version,
			Architecture: jsonProfile.Profile.Architecture,
		},
		Definition: &pb.SeccompProfileDefinition{
			DefaultAction: jsonProfile.Definition.DefaultAction,
			Architectures: jsonProfile.Definition.Architectures,
			Syscalls:      syscalls,
		}}, nil
}

func (s *Server) ExtendSeccompProfile(ctx context.Context, in *pb.ExtendSeccompProfileRequest) (*pb.BasicResponse, error) {
	err := s.authorizer.Authorize(ctx, "org.namespace.add", "org", util.GetOrgIdFromNamespace(in.ExtendProfile.Namespace))
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, err.Error())
	}
	if err := util.ValidateGetSeccompProfileRequest(in.GetDefineProfile()); err != nil {
		return nil, err
	}

	if err := util.ValidateGetSeccompProfileRequest(in.GetExtendProfile()); err != nil {
		return nil, err
	}
	redifined, err := repo.ExtendSeccompProfile(in)
	if err != nil {
		return nil, err
	}
	if redifined {
		return &pb.BasicResponse{Success: true, Message: "Your profile has been successfully created, but there was profile redifinion. Defining profile was not put into tree hierarchy"}, nil
	}
	return &pb.BasicResponse{Success: true, Message: "Your profile has been successfully created"}, nil
}

func (s *Server) GetAllDescendantProfiles(ctx context.Context, in *pb.SeccompProfile) (*pb.GetAllDescendantProfilesResponse, error) {
	err := s.authorizer.Authorize(ctx, "org.namespace.add", "org", util.GetOrgIdFromNamespace(in.Namespace))
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, err.Error())
	}

	response := pb.GetAllDescendantProfilesResponse{}
	jsonProfiles := repo.GetAllDescendantProfiles(in)
	for _, jsonProfile := range jsonProfiles {
		syscalls := make([]*pb.Syscalls, 0)
		for _, syscall := range jsonProfile.Definition.Syscalls {
			syscalls = append(syscalls, &pb.Syscalls{Names: syscall.Names, Action: syscall.Action})
		}
		profile := pb.SeccompProfileDefinitionRequest{
			Profile: &pb.SeccompProfile{Namespace: jsonProfile.Profile.Namespace,
				Application:  jsonProfile.Profile.Application,
				Name:         jsonProfile.Profile.Name,
				Version:      jsonProfile.Profile.Version,
				Architecture: jsonProfile.Profile.Architecture},
			Definition: &pb.SeccompProfileDefinition{DefaultAction: jsonProfile.Definition.DefaultAction,
				Architectures: jsonProfile.Definition.Architectures,
				Syscalls:      syscalls},
		}
		response.Profiles = append(response.Profiles, &profile)
	}
	return &response, nil
}

func (s *Server) GetSeccompProfileByPrefix(ctx context.Context, in *pb.SeccompProfile) (*pb.GetAllDescendantProfilesResponse, error) {
	e := util.ValidateGetSeccompProfileByPrefixRequest(in)
	if e != nil {
		return nil, e
	}
	response := pb.GetAllDescendantProfilesResponse{}
	jsonProfiles := repo.GetSeccompProfileByPrefix(in)
	for _, jsonProfile := range jsonProfiles {
		syscalls := make([]*pb.Syscalls, 0)
		for _, syscall := range jsonProfile.Definition.Syscalls {
			syscalls = append(syscalls, &pb.Syscalls{Names: syscall.Names, Action: syscall.Action})
		}
		profile := pb.SeccompProfileDefinitionRequest{
			Profile: &pb.SeccompProfile{Namespace: jsonProfile.Profile.Namespace,
				Application:  jsonProfile.Profile.Application,
				Name:         jsonProfile.Profile.Name,
				Version:      jsonProfile.Profile.Version,
				Architecture: jsonProfile.Profile.Architecture},
			Definition: &pb.SeccompProfileDefinition{DefaultAction: jsonProfile.Definition.DefaultAction,
				Architectures: jsonProfile.Definition.Architectures,
				Syscalls:      syscalls},
		}
		response.Profiles = append(response.Profiles, &profile)
	}
	return &response, nil
}

func GetAuthInterceptor() func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if ok && len(md.Get("authz-token")) > 0 {
			ctx = context.WithValue(ctx, "authz-token", md.Get("authz-token")[0])
		}
		return handler(ctx, req)
	}
}
