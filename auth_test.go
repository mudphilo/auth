package auth

import (
	"encoding/json"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	tokenutils "github.com/mudphilo/gwt"
	"github.com/stretchr/testify/assert"
	"log"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestGetToken(t *testing.T) {

	e := echo.New()
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	c := e.NewContext(req, rec)
	c.Set("_session_store", sessions.NewCookieStore([]byte("050a4c39ec6bff450e00017bc0b86157be2c91b6939c4935d5bad4c0258b6de9d1f99867502cf7e66977f4fac8b06e2ea1ed8cb1f6d9f52e79f1f109ba38065e")))

	t.Run("api-key", func(t *testing.T) {

		req.Header.Del("Authorization")
		req.Header.Del("x-token")
		req.Header.Del("api-key")

		req.Header.Set("api-key", "token")
		// Assertions
		token,_,_,_ := GetToken(c)

		assert.Equal(t, "token", token)
	})


	_ = os.Setenv("JWT_SECRET", "eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkphdmFJblVzZSIsImV4cCI6MTY2MzAxODY0NSwiaWF0IjoxNjYzMDE4NjQ1fQ.q9SwFW4jkhSpQKupbFOZVwdzQKnnsI73BZJZT-lDr1E")
	_ = os.Setenv("JWT_ISSUER", "da-mno.com")
	_ = os.Setenv("JWT_DURATION_HOURS", "72")
	_ = os.Setenv("ENV","tests")
	_ = os.Setenv("SERVICE_TOKEN","service")
	_ = os.Setenv("API_ENCRYPTION_KEY","e05b0e0d42c608dd08151cfc325da68f1eadd7bf60e457a043bc2e1de39635e2")

	t.Run("Authenticate with Authorization", func(t *testing.T) {

		var permissions []tokenutils.Permission
		permissions = append(permissions, tokenutils.Permission{
			Module:  MODULE_USER,
			Scope:   "all",
			Actions: []string{"create", "read", "update", "delete"},
		})

		permissions = append(permissions, tokenutils.Permission{
			Module:  MODULE_USER,
			Scope:   "",
			Actions: []string{"create", "read", "update", "delete"},
		})

		permissions = append(permissions, tokenutils.Permission{
			Module:  MODULE_PERMISSION,
			Scope:   "",
			Actions: []string{"create", "read", "update", "delete"},
		})

		authToken, err := tokenutils.CreateTokenWithClient(1,"sms",1,1, 1, "name", tokenutils.Role{
			Name:       "admin",
			Permission: permissions,
		})

		time.Sleep(30 * time.Second)
		assert.NoError(t, err)

		req.Header.Set("Authorization", authToken)

		_, _, _ = Authenticate(c,"user","create")
		//assert.True(t,authenticated)

	})

	t.Run("Authenticate with Authorization Self Auth", func(t *testing.T) {

		var permissions []tokenutils.Permission
		permissions = append(permissions, tokenutils.Permission{
			Module:  MODULE_USER,
			Scope:   "all",
			Actions: []string{"create", "read", "update", "delete"},
		})

		permissions = append(permissions, tokenutils.Permission{
			Module:  MODULE_USER,
			Scope:   "",
			Actions: []string{"create", "read", "update", "delete"},
		})

		permissions = append(permissions, tokenutils.Permission{
			Module:  MODULE_PERMISSION,
			Scope:   "",
			Actions: []string{"create", "read", "update", "delete"},
		})

		authToken, err := tokenutils.CreateTokenWithClient(1,"sms",1,1, 1, "name", tokenutils.Role{
			Name:       "admin",
			Permission: permissions,
		})
		assert.NoError(t, err)
		time.Sleep(30 * time.Second)

		req.Header.Set("Authorization", authToken)

		_, _, _ = Authenticate(c,"self","auth")
		//assert.True(t,authenticated)
	})

	t.Run("token key", func(t *testing.T) {

		req.Header.Del("Authorization")
		req.Header.Del("x-token")
		req.Header.Del("api-key")

		req.Header.Set("x-token", "service")
		// Assertions
		token,_,_,_ := GetToken(c)
		_, _, _ = Authenticate(c,"self","auth")

		assert.NotNil(t, token)
	})

	tokenData := TokenData{
		ClientID: 5,
		UserID:   2,
		Expiry: time.Now().Unix() + 5000,
	}

	tokenData.Permissions = []string{"USER","SMS","SETTINGS","CONFIG","CONTACTS","DDDD"}

	js, _ := json.Marshal(tokenData)

	tokenString, err := Encrypt(os.Getenv("API_ENCRYPTION_KEY"), string(js))
	if err != nil {

		log.Printf("error encrypting token %s ",err.Error())

	}

	t.Run("api key", func(t *testing.T) {

		req.Header.Del("Authorization")
		req.Header.Del("x-token")
		req.Header.Del("api-key")

		req.Header.Set("api-key", tokenString)
		// Assertions
		token,_,_,_ := GetToken(c)
		_, _, _ = Authenticate(c,"self","USER")

		assert.NotNil(t, token)
	})

	t.Run("Encrypt Decrypt", func(t *testing.T) {

		tokenData := TokenData{
			ClientID: 5,
			UserID:   2,
			Expiry: time.Now().Unix() + 5000,
		}

		tokenData.Permissions = []string{"USER","SMS","SETTINGS","CONFIG","CONTACTS","DDDD"}

		js, _ := json.Marshal(tokenData)
		tokenString, err := Encrypt(os.Getenv("API_ENCRYPTION_KEY"), string(js))
		if err != nil {

			log.Printf("error encrypting token %s ",err.Error())

		}

		plaintText, err := Decrypt(os.Getenv("API_ENCRYPTION_KEY"),tokenString)
		assert.NoError(t,err)

		res := new(TokenData)

		err = json.Unmarshal([]byte(plaintText), res)
		assert.NoError(t,err)

		assert.Equal(t,tokenData.ClientID, res.ClientID)

	})

}