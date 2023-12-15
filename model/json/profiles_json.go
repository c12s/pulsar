package json

type SyscallsJson struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

type ProfileDefinition struct {
	DefaultAction string         `json:"defaultAction"`
	Architectures []string       `json:"architectures"`
	Syscalls      []SyscallsJson `json:"syscalls"`
}

type Profile struct {
	Namespace    string `json:"namespace"`
	Application  string `json:"application"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}

type SeccompProfileJson struct {
	Profile    Profile           `json:"profile"`
	Definition ProfileDefinition `json:"definition"`
	Children   []string          `json:"children"`
}
