package jwtfiltergolang

import (
	"log"
	"strings"
)

//HasPermission hecks if the supplied token has the permission in the supplied module
func HasPermission(token, module, action, scope string) bool {

	// make it lower case
	module = strings.ToLower(module)
	action = strings.ToLower(action)

	// validate token
	claims, err := TokenValidation(token)
	if err != nil {

		log.Printf("error validating token %s ",err.Error())
		return false
	}

	// check if user has permisions
	return SliceContains(GetPermission(claims, module,scope).Actions, action)
}

func GetPermission(claims *JwtClaims, module,scope string) Permission {

	permission := Permission{
		Module:  "",
		Scope :"",
		Actions: nil,
	}

	// loop through a list of assigned permissions
	for _, r := range claims.Role.Permission {

		// check if supplied module matches and also if the action is in the list of assigned actions
		if r.Module == module && r.Scope == scope {

			// return tru if it matches
			permission = r
		}
	}

	return permission
}