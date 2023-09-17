# README #

### What is this repository for? ###

This is Golang lbrary to manage JWT tokens, with this you can generate a token, validate a token and check if the token has a specific prmission
### How do I get set up? ###


Then run go get command to download your library
```sh
go get -u github.com/mudphilo/gwt
go mod vendor
```

#### Setup environment variables (Secret key)

This library will read secret key from the environment variable name 
```sh
JWT_SECRET=SEcret Key
```
Setup the below envronment variables if you want to generate a token
```
JWT_ISSUER=Token issuer
JWT_DURATION_HOURS=token-lifetime-in-hour-must-be-int
```

This needs to be setup in your application, the key must be the same as the one used to generate the token
```go
jwtSecret := os.Getenv("JWT_SECRET")
```

#### Generate a token
The function needs
* user ID
* user name
* Assigned roles and permissions


```go
package mytest

import (
	tokenutils "github.com/mudphilo/gwt"
	"fmt"
)

func GenerateToken() {

	// create all permissions the user has
	var permissions []tokenutils.Permission
	permissions = append(permissions, tokenutils.Permission{
		Module:  "user",
		Actions: []string{"create", "read"},
	})

	permissions = append(permissions, tokenutils.Permission{
		Module:  "driver",
		Actions: []string{"read"},
	})
	username := "jondoe"
	userID := 1
	userStatus := 1

	token, err := tokenutils.CreateToken(userID, userStatus, username, tokenutils.Role{
		Name:       "admin",
		Permission: permissions,
	})

	if err != nil {

		fmt.Printf("invalid token got error %s", err.Error())
		return
	}

	if len(token) == 0 {

		fmt.Printf("invalid token")

	} else {

		fmt.Printf("Got token" + token)
	}

}

```

#### Decoding a token

```go
package mytest

import (
	tokenutils "github.com/mudphilo/gwt"
	"fmt"
)

func DecodeToken(token string) {

	claim, err := tokenutils.TokenValidation(token)
	if err != nil {
		fmt.Printf("invalid token")

	} else {
		fmt.Println(claim.UserId)
	}
}

```

#### Check if a token has the required permission
To check permissions we supply the token, module, action and scope

```go
package mytest

import (
	tokenutils "github.com/mudphilo/gwt"
	"fmt"
)

func CheckPermission(token string) {

	statusCheck := tokenutils.HasPermission(token, "location", "read", "own")
	if statusCheck {

		fmt.Printf("Token does not have permission to read own location")

	} else {
		fmt.Printf("Token has permission to read own location")
	}
}

```