package jwtfiltergolang

import "github.com/dgrijalva/jwt-go"

//Permission permissions model
type Permission struct {
	//Module name
	Module string `json:"module"`

	//Scope of the permission
	Scope string `json:"scope"`

	// permitted actions
	Actions []string `json:"actions"`
}

//Role roles object
type Role struct {
	ID int `json:"id"`
	//Name role name
	Name string             `json:"name"`

	//Permission array of all assigned permissions
	Permission []Permission `json:"permission"`
}

//JwtClaims JWT Models
type JwtClaims struct {
	//Tenant project name
	Tenant   string `json:"tenant"`

	//Tenant project name
	TenantID   int `json:"tenant_id"`

	//Tenant project name
	ClientID   int64 `json:"client_id"`

	//Username token username
	Username   string `json:"username"`

	//UserId ID associated with token
	UserId     int64    `json:"user_id"`

	//UserStatus status of the account associated with token
	UserStatus int    `json:"user_status"`

	//Role toles associated with the token
	Role       Role   `json:"role"`

	//Standard claims
	jwt.StandardClaims
}

func (c *JwtClaims) Valid() error {

	var leeway = int64(10)
	c.StandardClaims.IssuedAt -= leeway
	valid := c.StandardClaims.Valid()
	c.StandardClaims.IssuedAt += leeway

	return valid
}
