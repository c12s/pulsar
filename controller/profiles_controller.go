package controller

import (
	"context"
	"log"
	pb "pulsar/model/protobuf"
	repo "pulsar/repository"
	util "pulsar/util"
)

type Server struct {
	pb.UnimplementedSeccompServiceServer
}

func (s *Server) DefineSeccompProfile(ctx context.Context, in *pb.SeccompProfileDefinitionRequest) (*pb.BasicResponse, error) {
	log.Printf("Received: %v", in.GetProfile().GetNamespace())
	if err := util.ValidateDefineSeccompProfileRequest(in); err != nil {
		return nil, err
	}
	repo.CreateSeccompProfile(in)
	return &pb.BasicResponse{Success: true, Message: "Your profile has been successfully created"}, nil
}

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
