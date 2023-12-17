package util

import (
	"fmt"
	pb "pulsar/model/protobuf"
	repo "pulsar/repository"
)

func ValidateGetSeccompProfileRequest(request *pb.SeccompProfile) error {
	if request.GetNamespace() == "" {
		return fmt.Errorf("Namespace is required!")
	}
	if request.GetApplication() == "" {
		return fmt.Errorf("Application is required!")
	}
	if request.GetName() == "" {
		return fmt.Errorf("Profile Name is required!")
	}
	if request.GetArchitecture() == "" {
		return fmt.Errorf("Architecture is required!")
	}
	if request.GetVersion() == "" {

	}
	return nil

}

func ValidateDefineSeccompProfileRequest(request *pb.SeccompProfileDefinitionRequest) error {
	if request.GetProfile().GetNamespace() == "" {
		return fmt.Errorf("Namespace is required!")
	}
	if request.GetProfile().GetApplication() == "" {
		return fmt.Errorf("Application is required!")
	}
	if request.GetProfile().GetName() == "" {
		return fmt.Errorf("Profile name is required!")
	}
	if request.GetProfile().GetArchitecture() == "" {
		return fmt.Errorf("Architecture is required!")
	}
	if request.GetProfile().GetVersion() == "" {
		return fmt.Errorf("Version is required!")
	}
	if request.GetDefinition() == nil {
		return fmt.Errorf("Seccomp profile definition is required is required!")
	}

	_, e := repo.GetSeccompProfile(request.GetProfile())
	if e == nil {
		return fmt.Errorf("This profile already exists")
	}

	return nil
}

func ValidateGetSeccompProfileByPrefixRequest(request *pb.SeccompProfile) error {
	isFieldSet := func(field string) bool { // helper funcion
		return field != ""
	}

	if isFieldSet(request.Architecture) && (!isFieldSet(request.Namespace) || !isFieldSet(request.Application) || !isFieldSet(request.Name) || !isFieldSet(request.Version)) {
		return fmt.Errorf("Invalid request: Architecture is set, but preceding fields (Namespace, Application, Name, Version) are not set")
	}

	if isFieldSet(request.Version) && (!isFieldSet(request.Namespace) || !isFieldSet(request.Application) || !isFieldSet(request.Name)) {
		return fmt.Errorf("Invalid request: Version is set, but preceding fields (Namespace, Application, Name) are not set")
	}

	if isFieldSet(request.Name) && (!isFieldSet(request.Namespace) || !isFieldSet(request.Application)) {
		return fmt.Errorf("Invalid request: Name is set, but preceding fields (Namespace, Application) are not set")
	}

	if isFieldSet(request.Application) && !isFieldSet(request.Namespace) {
		return fmt.Errorf("Invalid request: Application is set, but preceding field (Namespace) is not set")
	}

	return nil
}
