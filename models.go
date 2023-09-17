package auth

type TokenData struct {
	ClientID int64 `json:"client_id"`
	UserID   int64 `json:"user_id"`
	RoleID   int64 `json:"role_id"`
	Expiry   int64 `json:"expiry"`
	Permissions []string `json:"permissions"`
}

type ResponseMessage struct {
	Status  int         `json:"status"`
	Message interface{} `json:"message"`
}