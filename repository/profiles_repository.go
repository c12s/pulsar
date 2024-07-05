package repository

import (
	"context"
	jsonenc "encoding/json"
	"fmt"
	"os"
	jsonmodel "pulsar/model/json"
	pb "pulsar/model/protobuf"
	"strings"
	"time"

	cli "go.etcd.io/etcd/client/v3"
	protojson "google.golang.org/protobuf/encoding/protojson"
)

var client *cli.Client

func init() {
	var err error
	client, err = cli.New(cli.Config{
		Endpoints:   []string{os.Getenv("ETCD_ADDRESS")},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return
	}
}

func CreateSeccompProfile(profile *pb.SeccompProfileDefinitionRequest) error {

	marshaledDefinition, _ := protojson.Marshal(profile.GetDefinition())
	json := jsonmodel.SeccompProfileJson{}
	e := jsonenc.Unmarshal([]byte(marshaledDefinition), &json.Definition)
	if e != nil {
		fmt.Printf("Unable to Unmarshall Extending Seccomp Profile")
		return e
	}
	json.Children = make([]string, 0)
	jsonBytes, _ := jsonenc.Marshal(struct {
		jsonmodel.SeccompProfileJson
		Profile interface{} `json:"profile,omitempty"`
	}{
		SeccompProfileJson: json,
	})

	_, err := client.Put(
		context.Background(),
		profile.GetProfile().GetNamespace()+"-"+profile.GetProfile().GetApplication()+"-"+profile.GetProfile().GetName()+"-"+profile.GetProfile().GetVersion()+"-"+profile.GetProfile().GetArchitecture(),
		string(jsonBytes))
	if err != nil {
		fmt.Printf("Error putting key-value pair: %v\n", err)
		return err
	}

	return nil
}

func GetSeccompProfile(profileRequest *pb.SeccompProfile) (*jsonmodel.SeccompProfileJson, error) {
	key := profileRequest.GetNamespace() + "-" + profileRequest.GetApplication() + "-" + profileRequest.GetName() + "-" + profileRequest.GetVersion() + "-" + profileRequest.GetArchitecture()
	response, err := client.Get(context.Background(), key)
	if err != nil {
		fmt.Printf("Error fetching key-value pair: %v\n", err)
	}
	if len(response.Kvs) == 0 {
		return nil, fmt.Errorf("profle not found")
	}
	profilejson := jsonmodel.SeccompProfileJson{}
	jsonenc.Unmarshal([]byte(response.Kvs[0].Value), &profilejson)
	return &profilejson, nil
}

func ExtendSeccompProfile(request *pb.ExtendSeccompProfileRequest) (bool, error) {
	var extendingProfileJson, _ = GetSeccompProfile(request.GetExtendProfile())
	if extendingProfileJson == nil {
		return false, fmt.Errorf("extending profile not found")
	}

	json := jsonmodel.SeccompProfileJson{}
	json.Definition = extendingProfileJson.Definition
	json.Children = make([]string, 0)

	redifined := false
	for _, reqSyscall := range request.GetSyscalls() {
		found := false
		for i, jsonSyscall := range json.Definition.Syscalls {
			if reqSyscall.GetAction() == jsonSyscall.Action {
				found = true
				// Union of names and put it in json.Definition.Syscalls[i].Names
				json.Definition.Syscalls[i].Names = union(jsonSyscall.Names, reqSyscall.GetNames())
			} else {
				for _, name := range reqSyscall.Names {
					for j, existingName := range jsonSyscall.Names {
						if name == existingName {
							redifined = true
							json.Definition.Syscalls[i].Names = append(json.Definition.Syscalls[i].Names[:j], json.Definition.Syscalls[i].Names[j+1:]...)
						}
					}
				}
				if len(json.Definition.Syscalls[i].Names) == 0 {
					json.Definition.Syscalls = append(json.Definition.Syscalls[:i], json.Definition.Syscalls[i+1:]...)
				}
			}
		}
		if !found {
			json.Definition.Syscalls = append(json.Definition.Syscalls, jsonmodel.SyscallsJson{
				Names:  reqSyscall.GetNames(),
				Action: reqSyscall.GetAction(),
			})
		}

	}
	if !redifined {
		extendingProfileJson.Children = append(extendingProfileJson.Children, request.DefineProfile.GetNamespace()+"-"+request.DefineProfile.GetApplication()+"-"+request.DefineProfile.GetName()+"-"+request.DefineProfile.GetVersion()+"-"+request.DefineProfile.GetArchitecture())
	}
	saveProfile(request.GetDefineProfile().GetNamespace()+"-"+request.GetDefineProfile().GetApplication()+"-"+request.GetDefineProfile().GetName()+"-"+request.GetDefineProfile().GetVersion()+"-"+request.GetDefineProfile().GetArchitecture(), json)
	// todo: deep copy
	// saveProfile(request.GetExtendProfile().GetNamespace()+"-"+request.GetExtendProfile().GetApplication()+"-"+request.GetExtendProfile().GetName()+"-"+request.GetExtendProfile().GetVersion()+"-"+request.GetExtendProfile().GetArchitecture(), *extendingProfileJson)
	return redifined, nil
}

func GetAllDescendantProfiles(profile *pb.SeccompProfile) []jsonmodel.SeccompProfileJson {

	var desendants []jsonmodel.SeccompProfileJson = make([]jsonmodel.SeccompProfileJson, 0)
	getAllDescendantsRecursive(profile.GetNamespace()+"-"+profile.GetApplication()+"-"+profile.GetName()+"-"+profile.GetVersion()+"-"+profile.GetArchitecture(), &desendants)
	return desendants
}

func GetSeccompProfileByPrefix(profile *pb.SeccompProfile) []jsonmodel.SeccompProfileJson {
	var retVal []jsonmodel.SeccompProfileJson = make([]jsonmodel.SeccompProfileJson, 0)
	var key string = ""
	if profile.GetNamespace() != "" {
		key += profile.GetNamespace() + "-"
	}
	if profile.GetApplication() != "" {
		key += profile.GetApplication() + "-"
	}
	if profile.GetName() != "" {
		key += profile.GetName() + "-"
	}
	if profile.GetVersion() != "" {
		key += profile.GetVersion() + "-"
	}
	if profile.GetArchitecture() != "" {
		key += profile.GetArchitecture()
	}
	profiles, _ := client.Get(context.Background(), key, cli.WithPrefix())
	for _, item := range profiles.Kvs {
		seccompProfileJson := jsonmodel.SeccompProfileJson{}
		var splitKey []string = strings.Split(string(item.Key), "-")
		seccompProfileJson.Profile.Namespace = splitKey[0]
		seccompProfileJson.Profile.Application = splitKey[1]
		seccompProfileJson.Profile.Name = splitKey[2]
		seccompProfileJson.Profile.Version = splitKey[3]
		seccompProfileJson.Profile.Architecture = splitKey[4]
		jsonenc.Unmarshal([]byte(item.Value), &seccompProfileJson)
		retVal = append(retVal, seccompProfileJson)

	}
	return retVal
}
func getAllDescendantsRecursive(key string, desendants *[]jsonmodel.SeccompProfileJson) {
	response, _ := client.Get(context.Background(), key)
	var splitKey []string = strings.Split(key, "-")
	profile := jsonmodel.SeccompProfileJson{Profile: jsonmodel.Profile{Namespace: splitKey[0],
		Application:  splitKey[1],
		Name:         splitKey[2],
		Version:      splitKey[3],
		Architecture: splitKey[4]}}
	jsonenc.Unmarshal(response.Kvs[0].Value, &profile)
	*desendants = append(*desendants, profile)
	for _, child := range profile.Children {
		getAllDescendantsRecursive(child, desendants)
	}

}
func union(slice1, slice2 []string) []string {
	set := make(map[string]struct{})
	result := []string{}

	for _, s := range slice1 {
		set[s] = struct{}{}
	}

	for _, s := range slice2 {
		if _, exists := set[s]; !exists {
			result = append(result, s)
		}
	}

	return append(slice1, result...)
}

func saveProfile(name string, profile jsonmodel.SeccompProfileJson) (bool, error) {
	jsonBytes, e := jsonenc.Marshal(struct {
		jsonmodel.SeccompProfileJson
		Profile interface{} `json:"profile,omitempty"`
	}{
		SeccompProfileJson: profile,
	})
	if e != nil {
		fmt.Println("Error Marshaling JSON:", e)
		return false, e
	}
	_, err := client.Put(
		context.Background(),
		name,
		string(jsonBytes))
	if err != nil {
		fmt.Printf("Error putting key-value pair: %v\n", err)
		return false, err
	}
	return true, nil
}
