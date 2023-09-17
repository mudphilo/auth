package auth

import (
	"encoding/json"
	"fmt"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	goutils "github.com/mudphilo/go-utils"
	jwtfiltergolang "github.com/mudphilo/gwt"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
	"strconv"
	"time"
)


func GetToken(c echo.Context) (token, username, password string, tokeType int64) {

	r := c.Request()

	token = r.Header.Get("Authorization")
	if len(token) > 0 {

		return token, "", "", TokenTypeAPI
	}

	token = r.Header.Get("x-token")
	if len(token) > 0 {

		return token, "", "", TokenServiceKey
	}

	token = r.Header.Get("api-key")
	if len(token) > 0 {

		return token, "", "", TokenTypeAPIKey
	}

	return "", "", "", TokenTypeUnknown

}

func Authenticate(c echo.Context, module, permission string) (bool, string, int) {

	token, _, _, tokenType := GetToken(c)
	var clientID, userID, roleID int64
	roleID = 0

	switch tokenType {

	case TokenServiceKey:

		if token != os.Getenv("SERVICE_TOKEN") {

			return false, "authorization failed, could not retieve token", http.StatusUnauthorized
		}

		roleID = 1
		userID = 1

		headerClientID, _ := strconv.ParseInt(c.Request().Header.Get("x-client-id"), 10, 64)
		headerUserID, _ := strconv.ParseInt(c.Request().Header.Get("x-user-id"), 10, 64)
		clientID = headerClientID

		if headerUserID > 0 {

			userID = headerUserID

		}

	case TokenTypeAPI:

		claims, err := jwtfiltergolang.TokenValidation(token)
		if err != nil {

			logrus.Errorf(TokenError, token, err.Error())
			return false, "authorization failed, could not retieve token", http.StatusUnauthorized
		}

		if module != "self" && permission != "auth" && !jwtfiltergolang.HasPermission(token, module, permission, "all") {

			logrus.Infof("API token %d has not %s permission on %s module ", claims.UserId, permission, module)
			return false, fmt.Sprintf(genericAuthFailed, permission, module), http.StatusPreconditionRequired
		}

		clientID = claims.ClientID
		userID = claims.UserId
		roleID = int64(claims.Role.ID)

	case TokenTypeAPIKey:

		tokenString, err := Decrypt(os.Getenv("API_ENCRYPTION_KEY"), token)
		if err != nil {

			logrus.Errorf(TokenError, token, err.Error())
			return false, "authorization failed, could not retrieve token", http.StatusUnauthorized

		}

		tokenData := new(TokenData)
		err = json.Unmarshal([]byte(tokenString), tokenData)
		if err != nil {

			logrus.Errorf(TokenError, token, err.Error())
			return false, "authorization failed, could not retrieve token", http.StatusUnauthorized

		}

		if tokenData.Expiry < time.Now().Unix() {

			return false, "Your token has expired, please generate a new one", http.StatusUnauthorized

		}

		if module != "self" && permission != "auth" {

			if !goutils.Contains(tokenData.Permissions, module) {

				return false, fmt.Sprintf(genericAuthFailed, permission, module), http.StatusPreconditionRequired
			}
		}

		clientID = tokenData.ClientID
		userID = tokenData.UserID
		roleID = tokenData.RoleID

	}

	sess, err := session.Get("session", c)
	if err != nil {

		logrus.Errorf("session bag error %s ", err.Error())
		return false, fmt.Sprintf(genericAuthFailed, permission, module), http.StatusInternalServerError
	}

	sess.Values["client_id"] = clientID
	sess.Values["user_id"] = userID
	sess.Values["role_id"] = roleID
	err = sess.Save(c.Request(), c.Response())
	if err != nil {

		logrus.Errorf("error saving session error %s ", err.Error())
		return false, fmt.Sprintf(genericAuthFailed, permission, module), http.StatusInternalServerError
	}

	return true, "", http.StatusOK
}

func ApiKey(pass echo.HandlerFunc, module string, permission string) echo.HandlerFunc {

	return func(c echo.Context) error {

		authenticated, message, httpStatus := Authenticate(c, module, permission)
		if authenticated {

			return pass(c)
		}

		return echo.NewHTTPError(httpStatus, ResponseMessage{
			Status:  httpStatus,
			Message: message,
		})
	}
}
