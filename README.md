# pulsar

Trees of Seccomp security profiles allowing restrictions on containers, inheritance and extend options to Seccomp security profiles used in distributed cloud platform.

# Requirements

- ETCD Database running (preferably on port **2379**) 
- Go version go1.20.6 or newer

# Setup

## Database:
	ETCD may run on Windows or Linux systems and can be Dockersied
	
### Linux setup:
- Clone the repo
	`git clone -b v3.5.0 https://github.com/etcd-io/etcd.git`
- Change directory
	`cd etcd`
- Run the build script
	`./build.sh`
-  Add the full path to the `bin` directory to your path, for example
	`export  PATH="$PATH:`pwd`/bin"`
- Test that `etcd` is in your path:
	`etcd --version`
- Run ETCD database
	`etcd`

# Service Usage
Service currently has 5 **grcp** endpoints defined:

 - GetSeccompProfile
 - DefineSeccompProfile
 - ExtendSeccompProfile
 - GetAllDescendantProfiles
 
 **GetSeccompProfile** - Takes in Namespace, Application, Name, Version and Architecture as input. Returns Seccomp Profile if it is found in the database. Otherwise, provides a message of unsuccessful fetching.
 **DefineSeccompProfile**  Takes in Namespace, Application, Name, Version, Architecture and **Seccomp profile definition** as input. If the name of profile is unique, profile is created. Otherwise, client is notified of failed action.
 **ExtendSeccompProfile** Takes in name of **extending** and name of **defining** profile. May take an optional parameter in form of **syscalls** (additional system calls which defining profile should add onto its definition) If syscalls are provided as parameter, user may expect 2 scenarios:
- Defining profile extends an extending profile and adds syscalls
- Added syscalls are in conflict with existing syscalls from extending profile (eg. extending profile has **mkdir** as forbidden action while syscalls coming from the request define **mkdir** as allowed action.  In this case **priority is given to syscalls parameter**. User is notified that there was a conflict resulting in **successful profile creattion** but the defined profile **won't be added as a child in hierarchy to extending profile**
- **GetAllDescendantProfiles** - Takes the same input as **GetSeccompProfile** but returns a list of all descendants in tree hierarchy of provided profile.