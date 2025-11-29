package types

type LoginRequest struct {
	PhoneNumber string `json:"phone_number"` // Field to allow login via email or phone
	Redirect    string `json:"redirect,omitempty"`
	Password    string `json:"password"`
}

func (r LandRequest) Validate() string {
	// Ensure that login identifier is provided (either email or phone)
	if r.Access == "" {
		return "Access token is required"
	}

	// Validate refresh token
	if r.Refresh == "" {
		return "Refresh token is required"
	}
	return ""
}

type LoginDMSRequest struct {
	UserName string `json:"username"` // Field to allow login via email or phone
	Password string `json:"password"`
}

type ErrorResponse struct {
	Message string `json:"message"`
	Status  int    `json:"status"`
}

type LandRequest struct {
	Access  string `json:"access"` // Field to allow login via email or phone
	Refresh string `json:"refresh"`
}

type LoginUserResponse struct {
	Status          string        `json:"status"`
	DMSToken        string        `json:"dms_token"`
	RMSCode         string        `json:"rms_code"`
	BranchCode      string        `json:"branch_code"`
	UserGroup       string        `json:"user_group"`
	User            UserLoginData `json:"user"`
	SSOAccessToken  string        `json:"sso_access_token"`
	SSORefreshToken string        `json:"sso_refresh_token"`
}

type CreatedByData struct {
	UUID        string `json:"uuid"`
	PhoneNumber string `json:"phone_number"`
}

type ApprovedByData struct {
	UUID        string `json:"uuid"`
	PhoneNumber string `json:"phone_number"`
}

type UserLoginData struct {
	TokenType     string          `json:"token_type"`
	Exp           int64           `json:"exp"`
	Iat           int64           `json:"iat"`
	Jti           string          `json:"jti"`
	UUID          string          `json:"uuid"`
	Nonce         int             `json:"nonce"`
	Avatar        string          `json:"avatar"`
	Username      string          `json:"username"`
	LegalName     *string         `json:"legal_name"`
	Phone         string          `json:"phone"`
	PhoneVerified bool            `json:"phone_verified"`
	Email         *string         `json:"email"`
	EmailVerified bool            `json:"email_verified"`
	CreatedBy     *CreatedByData  `json:"created_by"`
	ApprovedBy    *ApprovedByData `json:"approved_by"`
	Permissions   []string        `json:"permissions"`
}

// custom error message
func (r LoginRequest) Validate() string {
	// Ensure that login identifier is provided (either email or phone)
	if r.PhoneNumber == "" {
		return "Either email or phone is required"
	}

	// Validate password
	if r.Password == "" {
		return "Password is required"
	}
	return ""
}
