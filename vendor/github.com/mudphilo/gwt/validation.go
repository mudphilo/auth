package jwtfiltergolang

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"os"
	"time"
)

//TokenValidation validate is the supplied token is valid
func TokenValidation(tokenString string) (*JwtClaims, error) {

	// get secret from environment variable
	jwtSecret := os.Getenv("JWT_SECRET")

	var keyfunc jwt.Keyfunc = func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	}

	token, err := jwt.Parse(tokenString, keyfunc)
	if err != nil {

		log.Printf("Failed to parse JWT.\nError: %s", err.Error())
		return nil, err
	}

	if !token.Valid {

		log.Print("error validating token is not valid")
		return nil, fmt.Errorf("error validating token is not valid")

	}

	js, err := json.Marshal(token.Claims)
	if err != nil {

		log.Printf("Failed to Marshal claims.\nError: %s", err.Error())
		return &JwtClaims{}, err

	}
	jwtClaims := new(JwtClaims)
	err = json.Unmarshal(js,jwtClaims)
	if err != nil {

		log.Printf("Failed to Unmarshal claims.\nError: %s", err.Error())
		return jwtClaims, err

	}

	// check expiry date of the token
	if jwtClaims.ExpiresAt < time.Now().UTC().Unix() {

		return &JwtClaims{}, errors.New("token is expired")

	}

	return jwtClaims, nil
}
