package jwtfiltergolang

import (
	"github.com/dgrijalva/jwt-go"
	"log"
	"os"
	"strconv"
	"time"
)

//CreateToken create a new token from the supplied input
func CreateToken(userId int, userStatus int, userName string, role Role) (string, error) {

	// get parametrs from environment variables
	secret := os.Getenv("JWT_SECRET")
	issuer := os.Getenv("JWT_ISSUER")
	durationStr := os.Getenv("JWT_DURATION_HOURS")

	// convert duration to int
	duration, err := strconv.Atoi(durationStr)
	if err != nil {

		log.Printf("error concerting duration to int %s",err.Error())
		return "", err
	}

	// construct claims object
	claims := &JwtClaims{
		UserId:     int64(userId),
		UserStatus: userStatus,
		Username:   userName,
		Role:       role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(duration)).Unix(), //1_500_000,
			Issuer:    issuer,
			IssuedAt: time.Now().UnixNano() * 1000 * 1000,
		},
	}

	// generate token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// sign token
	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {

		log.Printf("error signing token %s",err.Error())
		return "", err
	}

	return signedToken, nil

}

func CreateTokenWithClient(tenantID int, tenantName string, clientID , userId int64, userStatus int, userName string, role Role) (string, error) {

	// get parametrs from environment variables
	secret := os.Getenv("JWT_SECRET")
	issuer := os.Getenv("JWT_ISSUER")
	durationStr := os.Getenv("JWT_DURATION_HOURS")

	// convert duration to int
	duration, err := strconv.ParseFloat(durationStr,64)
	if err != nil {

		log.Printf("error concerting duration to int %s",err.Error())
		duration = 1
	}

	// construct claims object
	claims := &JwtClaims{
		Tenant: tenantName,
		TenantID: tenantID,
		ClientID: clientID,
		UserId:     userId,
		UserStatus: userStatus,
		Username:   userName,
		Role:       role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(duration)).Unix(), //1_500_000,
			Issuer:    issuer,
			IssuedAt: time.Now().Unix(),
		},
	}

	// generate token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// sign token
	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {

		log.Printf("error signing token %s",err.Error())
		return "", err
	}

	return signedToken, nil

}
