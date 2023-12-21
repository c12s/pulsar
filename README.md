
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

- Add the full path to the `bin` directory to your path, for example

`export PATH="$PATH:`pwd`/bin"`

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

  
  

**DefineSeccompProfile** Takes in Namespace, Application, Name, Version, Architecture and **Seccomp profile definition** as input. If the name of profile is unique, profile is created. Otherwise, client is notified of failed action.

  
  

**ExtendSeccompProfile** Takes in name of **extending** and name of **defining** profile. May take an optional parameter in form of **syscalls** (additional system calls which defining profile should add onto its definition) If syscalls are provided as parameter, user may expect 2 scenarios:

  

- Defining profile extends an extending profile and adds syscalls

- Added syscalls are in conflict with existing syscalls from extending profile (eg. extending profile has **mkdir** as forbidden action while syscalls coming from the request define **mkdir** as allowed action. In this case **priority is given to syscalls parameter**. User is notified that there was a conflict resulting in **successful profile creattion** but the defined profile **won't be added as a child in hierarchy to extending profile**

  
  

**GetAllDescendantProfiles** - Takes the same input as **GetSeccompProfile** but returns a list of all descendants in tree hierarchy of provided profile.

# Callout examples
### Get Seccomp Profile
**Endpoint**: `GetSeccompProfile`

**Request Body**:
```
{
    "namespace" : "namespace",
    "application" : "application",
    "name" : "profileName",
    "version" : "v1",
    "architecture" : "x86"
}
```

**Response**:
```
{
	"profile": "{\"defaultAction\":\"ALLOW\",\"architectures\":[\"x86\"],\"syscalls\":[{\"names\":[\"DELETE\",\"MKDIR\"],\"action\":\"ALLOW\"}]}"
}
```

### NOTE: '\\' character is added during protobuf serialization. In ETCD database, JSON is saved as is...

### Define Seccomp Profile
**Endpoint**: `DefineSeccompProfile`

**Request Body**:
```{
    "profile": {
        "namespace" : "namespace",
        "application" : "application",
        "name" : "profileName",
        "version" : "v1",
        "architecture" : "x86"
        },
    "definition": {
        "defaultAction" : "ALLOW",
        "architectures" : ["x86"],
        "syscalls" : [
            {
                "names" : ["DELETE", "MKDIR"],
                "action" : "ALLOW"
            }
        ]
    }
}
```

**Response**:
`{"success": true,
"message": "Your profile has been successfully created"
}`


### Extend Seccomp Profile

**Endpoint**: `ExtendSeccompProfile`

**Request Body**:
```
{
	"extendProfile": {
        "namespace" : "someNameSpace",
        "application" : "someApplication",
        "name" : "someName",
        "version" : "v1",
        "architecture" : "x86"
        },
	"defineProfile": {
        "namespace" : "someNamespace",
        "application" : "someOTHERapp",
        "name" : "profile",
        "version" : "v1",
        "architecture" : "x86"
        },
        "syscalls" : [
            {
                "names" : ["DELETE"],
                "action" : "ALLOW"
            }
        ]
 }
 ```
 
**Response**:
`{"success": true,
"message": "Your profile has been successfully created"
}`

### Define Multiple Seccomp Profiles (Batch)
**Endpoint**: `DefineSeccompProfileBatch`

**Request Body**:
```
{
	"profiles": [
	{
			"profile": {
			"namespace" : "namespace",
			"application" : "application",
			"name" : "someName1",
			"version" : "v1",
			"architecture" : "x86"
			},
			"definition": {
			"defaultAction" : "AA",
			"architectures" : ["x86", "x99"],
			"syscalls" : [
				{
					"names" : ["DELETE"],
					"action" : "ALLOW"
				}
			]
		}
	},
{
			"profile": {
			"namespace" : "namespace",
			"application" : "application",
			"name" : "someName2",
			"version" : "v1",
			"architecture" : "x86"
			},
			"definition": {
			"defaultAction" : "AA",
			"architectures" : ["x86", "x99"],
			"syscalls" : [
				{
					"names" : ["DELETE"],
					"action" : "ALLOW"
				}
			]
		}
	},
{
		"profile": {
		"namespace" : "namespace",
		"application" : "application",
		"name" : "someName1",
		"version" : "v1",
		"architecture" : "x86"
		},
		"definition": {
		"defaultAction" : "AA",
		"architectures" : ["x86", "x99"],
		"syscalls" : [
			{
				"names" : ["DELETE"],
				"action" : "ALLOW"
			}
		]
	}
	}
]
}
```
 
**Response**:
`{
"success": true,
"message": "Batch completed. Profiles successfully created"
}`

### Get All Descendant Profiles in tree hierarchy

**Endpoint**: `GetAllDescendantProfiles`

**Request Body**:
```
{
    "namespace" : "namespace",
    "application" : "application",
    "name" : "profileName",
    "version" : "v1",
    "architecture" : "x86"
}
```
 
**Response**:
```
{
"profiles": [
{
	"profile": {
		"namespace": "namespace",
		"application": "application",
		"name": "profileName",
		"version": "v1",
		"architecture": "x86"
	},
	"definition": {
		"architectures": [
		"x86"
		],
		"syscalls": [
		{
		"names": ["DELETE","MKDIR"],
		"action": "ALLOW"
		}],
		"defaultAction": "ALLOW"
			}
		}
	]
}
```

### Get Seccomp Profiles by Prefix Search

**Endpoint** `GetSeccompProfilesByPrefix`

**Request** 
`{
    "namespace" : "namespace"
}`

**Response**
```
{
	"profiles": [
	{
		"profile": {
		"namespace": "namespace",
		"application": "application",
		"name": "profileName",
		"version": "v1",
		"architecture": "x86"
	},
	"definition": {
		"architectures": [
		"x86"
		],
		"syscalls": [
		{
			"names": ["DELETE","MKDIR"],
			"action": "ALLOW"
		}
		],
		"defaultAction": "ALLOW"
		}
	}
	]
}
```

### Note: The Request Body can be the same as in GetSeccompProfile. Profiles names are saved in database in next format:

**namespace-application-profileName-version-architecture**

Therefore, namespace is the only field needed for prefix profile search. Rest of them are optional.**It's not possible to provide arguments which break the order.** For example, if you provide namespace, you can provide application as well, but you cant provide profile name or version or architecture as you are missing an application argument in your prefix search. You can only provide Profile Name **IF YOU ALREADY HAVE PROVIDED NAMESPACE AND APPLICATION** and so on. Also, it is possible to provide only the 'begining string' of the **LAST ARGUMENT**. These would also be valid requests:

`{ "namespace" : "namesp" }`

This would return all the profiles from the database whose namespace starts with **namesp**. Another example of the valid request:

`{ "namespace" : "namespace", "application": "application", "profile" :"pro"}`


This would return all the profiles from the database whose keys starts with **namespace-application-pro**. 


`
