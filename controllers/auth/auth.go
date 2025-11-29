package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"passport-booking/database"
	httpServices "passport-booking/httpServices/sso"
	"passport-booking/logger"
	sso "passport-booking/middleware"
	"passport-booking/models/user"
	"passport-booking/types"
	"passport-booking/utils"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AuthController struct {
	db             *gorm.DB
	httpService    *httpServices.SSOClient
	loggerInstance *logger.AsyncLogger
}

func NewAuthController(service *httpServices.SSOClient, db *gorm.DB, async_logger *logger.AsyncLogger) *AuthController {
	return &AuthController{httpService: service, db: db, loggerInstance: async_logger}
}

// Helper function to set secure cookies based on environment
func (h *AuthController) setSecureCookie(c *fiber.Ctx, name, value string, maxAge int) {
	isProduction := os.Getenv("APP_ENV") == "production"

	c.Cookie(&fiber.Cookie{
		Name:     name,
		Value:    value,
		HTTPOnly: false,
		Secure:   isProduction, // Only secure in production (HTTPS)
		SameSite: "Strict",
		MaxAge:   maxAge,
		Path:     "/",
	})
}

func (h *AuthController) Register(c *fiber.Ctx) error {
	// Parse the request body as JSON
	var req types.RegisterUserRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Error("Error parsing request body", err)
		response := types.ErrorResponse{
			Message: fmt.Sprintf("Error parsing request body: %v", err),
			Status:  fiber.StatusBadRequest,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	// Get the access token from Authorization header
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		logger.Error("Authorization header missing", nil)
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrorResponse{
			Message: "Authorization token required",
			Status:  fiber.StatusUnauthorized,
		})
	}

	// Extract Bearer token
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		logger.Error("Invalid authorization header format", nil)
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrorResponse{
			Message: "Invalid authorization header format",
			Status:  fiber.StatusUnauthorized,
		})
	}

	accessToken := tokenParts[1] // Extract the actual token

	// Validate request
	if validationErr := req.Validate(); validationErr != "" {
		logger.Error(validationErr, nil)
		response := types.ErrorResponse{
			Message: validationErr,
			Status:  fiber.StatusBadRequest,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	// Make call to external API through the service
	registerResponse, err := h.httpService.RequestRegisterUser(types.RegisterUserRequest{
		PhoneNumber: req.PhoneNumber,
		Token:       req.Token,
		Password:    req.Password,
		Username:    req.Username,
		Access:      accessToken, // Pass the extracted access token
	})
	// fmt.Println("Register Response: ", registerResponse)
	if err != nil {
		logger.Error("Failed to login user", err)
		return c.Status(fiber.StatusBadGateway).JSON(types.ErrorResponse{
			Message: "Failed to login user",
			Status:  fiber.StatusBadGateway,
		})
	}

	currentTime := time.Now().Format("2006-01-02 03:04:05 PM")

	// If registration was successful, create user in local database
	if registerResponse.Status == "success" && registerResponse.User.UUID != "" {
		// Create user in local database
		newUser := user.User{
			Uuid:          registerResponse.User.UUID,
			Username:      registerResponse.User.Username,
			Phone:         registerResponse.User.PhoneNumber,
			PhoneVerified: false, // Set to false initially as SMS is sent for verification
			EmailVerified: false,
			LegalName:     "",                 // Set to empty string if null in response
			Avatar:        "",                 // Set to empty string if null in response
			Nonce:         0,                  // Default value
			Permissions:   user.StringSlice{}, // Empty permissions array
		}

		// Handle nullable fields
		if registerResponse.User.Email != nil && *registerResponse.User.Email != "" {
			newUser.Email = registerResponse.User.Email
		}
		// Email remains nil if not provided or empty
		if registerResponse.User.LegalName != nil {
			newUser.LegalName = *registerResponse.User.LegalName
		}
		if registerResponse.User.Avatar != nil {
			newUser.Avatar = *registerResponse.User.Avatar
		}

		// Create user in database
		if err := database.DB.Create(&newUser).Error; err != nil {
			logger.Error("Failed to create user in local database", err)
			// Note: We still return success since external registration succeeded
			// This is just a local database sync issue
		} else {
			logger.Success("User created in local database successfully. UUID: " + newUser.Uuid)
		}
	}

	logEntry := utils.CreateSanitizedLogEntry(c)
	h.loggerInstance.Log(logEntry)

	logger.Success("User registered in successfully." + " at " + currentTime)
	return c.Status(fiber.StatusOK).JSON(registerResponse)
	// // Start Transaction
	// tx := database.DB.Begin()

	// // Create user
	// createUser := models.User{
	// 	Uuid:          uuid.NewString(),
	// 	Username:      req.Username,
	// 	LegalName:     req.LegalName,
	// 	Phone:         req.Phone,
	// 	PhoneVerified: false,
	// 	Email:         req.Email,
	// 	EmailVerified: false,
	// 	Avatar:        "", // or req.Avatar if available
	// 	Nonce:         0,  // default value, update as needed
	// 	CreatedBy:     nil,
	// 	ApprovedBy:    nil,
	// 	Permissions:   []string{},
	// }

	// if err := tx.Create(&createUser).Error; err != nil {
	// 	tx.Rollback()
	// 	logger.Error("Failed to create user", err)
	// 	return c.Status(fiber.StatusInternalServerError).JSON(types.ApiResponse{
	// 		Message: fmt.Sprintf("Failed to create user: %v", err),
	// 		Status:  fiber.StatusInternalServerError,
	// 	})
	// }

	// tx.Commit()

}

func (h *AuthController) Land(c *fiber.Ctx) error {
	// 1) Parse & validate
	var req types.LandRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Error("Error parsing request body", err)
		return c.Status(fiber.StatusBadRequest).JSON(types.ApiResponse{
			Message: fmt.Errorf("Error parsing request body: %v", err).Error(),
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		})
	}

	if v := req.Validate(); v != "" {
		logger.Error(v, nil)
		return c.Status(fiber.StatusBadRequest).JSON(types.ApiResponse{
			Message: v,
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		})
	}

	// 2) Verify JWT and extract claims
	claims, err := sso.VerifyJWT(req.Access)
	log.Println("Verifying JWT token...", claims)
	if err != nil {
		log.Printf("JWT verification failed: %v", err)
		return c.Status(fiber.StatusUnauthorized).JSON(types.ApiResponse{
			Message: "Invalid or expired token",
			Status:  fiber.StatusUnauthorized,
			Data:    nil,
		})
	}
	fmt.Println("Verified JWT claims:", claims)

	// 3) Extract user data from claims
	uid, ok := claims["uuid"].(string)
	if !ok || strings.TrimSpace(uid) == "" {
		logger.Error("UUID not found in JWT claims", nil)
		return c.Status(fiber.StatusBadRequest).JSON(types.ApiResponse{
			Message: "Invalid token: UUID missing",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		})
	}

	nowStr := time.Now().Format("2006-01-02 03:04:05 PM")

	// 4) Upsert user + EnsureUserAccount in one transaction (similar to login logic)
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		var u user.User

		// Pull required claim(s)
		uid, _ := claims["uuid"].(string)
		username, _ := claims["username"].(string)
		phone, _ := claims["phone"].(string)

		// (1) Try by USERNAME first
		if strings.TrimSpace(username) != "" {
			if err := tx.Where("username = ?", username).First(&u).Error; err == nil {
				// If DB uuid differs (or empty), overwrite with token uuid
				if strings.TrimSpace(uid) != "" && u.Uuid != uid {
					logger.Info(fmt.Sprintf("Username match; updating UUID %q -> %q for user ID %d", u.Uuid, uid, u.ID))
					u.Uuid = uid
				}
				applyClaimsToUser(&u, claims)
				// ensurePostMasterSystemAccount(tx, &u, claims)
				if err := tx.Save(&u).Error; err != nil {
					return fmt.Errorf("update user by username failed: %w", err)
				}
				// if _, err := EnsureUserAccount(tx, u.ID); err != nil {
				// 	return fmt.Errorf("ensure user-account failed: %w", err)
				// }
				return nil
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("query user by username failed: %w", err)
			}
		}

		// (2) Try by UUID
		if strings.TrimSpace(uid) != "" {
			if err := tx.Where("uuid = ?", uid).First(&u).Error; err == nil {
				applyClaimsToUser(&u, claims)
				// ensurePostMasterSystemAccount(tx, &u, claims)
				if err := tx.Save(&u).Error; err != nil {
					return fmt.Errorf("update user by uuid failed: %w", err)
				}
				// if _, err := EnsureUserAccount(tx, u.ID); err != nil {
				// 	return fmt.Errorf("ensure user-account failed: %w", err)
				// }
				return nil
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("query user by uuid failed: %w", err)
			}
		}

		// (3) Try by PHONE
		if strings.TrimSpace(phone) != "" {
			if err := tx.Where("phone = ?", phone).First(&u).Error; err == nil {
				// Attach SSO uuid if missing/different
				if strings.TrimSpace(uid) != "" && u.Uuid != uid {
					logger.Info(fmt.Sprintf("Phone match; updating UUID %q -> %q for user ID %d", u.Uuid, uid, u.ID))
					u.Uuid = uid
				}
				applyClaimsToUser(&u, claims)
				// ensurePostMasterSystemAccount(tx, &u, claims)
				if err := tx.Save(&u).Error; err != nil {
					return fmt.Errorf("merge user by phone failed: %w", err)
				}
				// if _, err := EnsureUserAccount(tx, u.ID); err != nil {
				// 	return fmt.Errorf("ensure user-account failed: %w", err)
				// }
				return nil
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("query user by phone failed: %w", err)
			}
		}

		// (4) Create NEW user (none matched)
		nu := user.User{Uuid: uid}
		applyClaimsToUser(&nu, claims)
		// set PostOfficeBranch / post-master system account inside helper after nu has an ID
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&nu).Error; err != nil {
			return fmt.Errorf("create user failed: %w", err)
		}
		if err := tx.Where("uuid = ?", uid).First(&nu).Error; err != nil {
			return fmt.Errorf("fetch created user failed: %w", err)
		}
		// ensurePostMasterSystemAccount(tx, &nu, claims)
		if err := tx.Save(&nu).Error; err != nil {
			return fmt.Errorf("finalize new user failed: %w", err)
		}
		// if _, err := EnsureUserAccount(tx, nu.ID); err != nil {
		// 	return fmt.Errorf("ensure user-account failed: %w", err)
		// }
		return nil
	}); err != nil {
		logger.Error("Land DB transaction failed", err)
		return c.Status(fiber.StatusInternalServerError).JSON(types.ApiResponse{
			Message: "Token verified but local sync failed",
			Status:  fiber.StatusInternalServerError,
			Data:    nil,
		})
	}

	// 5) Structured log
	h.loggerInstance.Log(types.LogEntry{
		Method:          c.Method(),
		URL:             c.OriginalURL(),
		RequestBody:     string(c.Body()),
		ResponseBody:    `{"message": "Land successful", "status": 200}`,
		RequestHeaders:  string(c.Request().Header.Header()),
		ResponseHeaders: string(c.Response().Header.Header()),
		StatusCode:      fiber.StatusOK,
		CreatedAt:       time.Now(),
	})

	logger.Success("User landed successfully. uuid: " + uid + " at " + nowStr)
	return c.Status(fiber.StatusOK).JSON(types.ApiResponse{
		Message: "Land successful",
		Status:  fiber.StatusOK,
		Data: map[string]interface{}{
			"uuid": uid,
		},
	})
}

func applyClaimsToUser(u *user.User, claims map[string]interface{}) {
	if username, ok := claims["username"].(string); ok && username != "" {
		u.Username = username
	}
	if phone, ok := claims["phone"].(string); ok {
		u.Phone = phone
	}
	if pv, ok := claims["phone_verified"].(bool); ok {
		u.PhoneVerified = pv
	}
	if ev, ok := claims["email_verified"].(bool); ok {
		u.EmailVerified = ev
	}
	if avatar, ok := claims["avatar"].(string); ok {
		u.Avatar = avatar
	}
	if nonce, ok := claims["nonce"].(float64); ok {
		u.Nonce = int(nonce)
	}
	if legalName, ok := claims["legal_name"].(string); ok && legalName != "" {
		u.LegalName = legalName
	}
	if email := claims["email"]; email != nil {
		if emailStr, ok := email.(string); ok && emailStr != "" {
			u.Email = &emailStr
		}
	}
	if permissions, ok := claims["permissions"].([]interface{}); ok {
		var permStrings []string
		for _, p := range permissions {
			if pStr, ok := p.(string); ok {
				permStrings = append(permStrings, pStr)
			}
		}
		u.Permissions = user.StringSlice(permStrings)
	}
}

func (h *AuthController) Login(c *fiber.Ctx) error {
	var req types.LoginDMSRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Error("Error parsing request body", err)
		response := types.ApiResponse{
			Message: fmt.Errorf("Error parsing request body: %v", err).Error(),
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	// Validate request
	//if validationError := req.Validate(); validationError != "" {
	//	logger.Error(validationError, nil)
	//	response := types.ApiResponse{
	//		Message: validationError,
	//		Status:  fiber.StatusBadRequest,
	//		Data:    nil,
	//	}
	//	return c.Status(fiber.StatusBadRequest).JSON(response)
	//}

	// Make call to external API through the service
	loginResponse, err := h.httpService.RequestDMSLoginUser(types.LoginDMSRequest{
		UserName: req.UserName,
		Password: req.Password,
	})
	if err != nil {
		logger.Error("Failed to login user", err)
		return c.Status(fiber.StatusBadGateway).JSON(types.ApiResponse{
			Message: "Failed to login user",
			Status:  fiber.StatusBadGateway,
		})
	}

	currentTime := time.Now().Format("2006-01-02 03:04:05 PM")

	// Check if user exists in local database, create if not exists
	if loginResponse.Status == "success" && loginResponse.User.UUID != "" {
		fmt.Println("Login Response Data: ")
		var existingUser user.User
		result := database.DB.Where("uuid = ?", loginResponse.User.UUID).First(&existingUser)

		if result.Error != nil {
			// User doesn't exist, create new user
			newUser := user.User{
				Uuid:          loginResponse.User.UUID,
				Username:      loginResponse.User.Username,
				Phone:         loginResponse.User.Phone,
				PhoneVerified: loginResponse.User.PhoneVerified,
				EmailVerified: loginResponse.User.EmailVerified,
				Avatar:        loginResponse.User.Avatar,
				Nonce:         loginResponse.User.Nonce,
				Permissions:   user.StringSlice(loginResponse.User.Permissions),
			}

			// Handle nullable fields
			if loginResponse.User.LegalName != nil {
				newUser.LegalName = *loginResponse.User.LegalName
			}
			if loginResponse.User.Email != nil && *loginResponse.User.Email != "" {
				newUser.Email = loginResponse.User.Email
			}
			// Email remains nil if not provided or empty

			// Handle CreatedBy and ApprovedBy if they exist in the response
			// For now, we'll just store the UUIDs if needed
			// You might want to implement logic to find and link existing users

			// Create user in database
			if err := database.DB.Create(&newUser).Error; err != nil {
				logger.Error("Failed to create user in local database", err)
				// Continue with login even if local database sync fails
			} else {
				logger.Success("User created in local database successfully. UUID: " + newUser.Uuid)
			}
		} else {
			// User exists, optionally update their information
			fmt.Printf("User already exists in local database. UUID: %s\n", existingUser.Uuid)
		}
	}
	// Set HTTP-only secure cookies for access and refresh tokens
	if loginResponse.SSOAccessToken != "" {
		h.setSecureCookie(c, "access", loginResponse.SSOAccessToken, 8*60*60) // 8 hours
	}

	if loginResponse.SSORefreshToken != "" {
		h.setSecureCookie(c, "refresh", loginResponse.SSORefreshToken, 7*24*60*60) // 7 days
	}

	// Marshal loginResponse to JSON string for logging
	responseBodyStr := ""
	if loginResponse != nil {
		if b, err := json.Marshal(loginResponse); err == nil {
			responseBodyStr = string(b)
		}
	}

	logEntry := utils.CreateSanitizedLogEntryWithCustomBody(c, string(c.Body()), responseBodyStr)
	h.loggerInstance.Log(logEntry)

	logger.Success("User logged in successfully. uuid: " + loginResponse.User.UUID + " at " + currentTime)
	return c.Status(fiber.StatusOK).JSON(loginResponse)
}

func (h *AuthController) GetServiceToken(c *fiber.Ctx) error {
	var req types.GetServiceTokenRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Error("Error parsing request body", err)
		return c.Status(fiber.StatusBadRequest).JSON(types.ApiResponse{
			Message: "Invalid request payload",
			Status:  fiber.StatusBadRequest,
		})
	}

	if validationErr := req.Validate(); validationErr != "" {
		logger.Error(validationErr, nil)
		return c.Status(fiber.StatusBadRequest).JSON(types.ApiResponse{
			Message: validationErr,
			Status:  fiber.StatusBadRequest,
		})
	}

	// Make call to external API through the service
	redirectToken, err := h.httpService.RequestRedirectToken(httpServices.ServiceUserRequest{
		InternalIdentifier: req.InternalIdentifier,
		RedirectURL:        req.RedirectURL,
		UserType:           req.UserType,
	})
	if err != nil {
		logger.Error("Failed to retrieve redirect token", err)
		return c.Status(fiber.StatusBadGateway).JSON(types.ApiResponse{
			Message: "Failed to communicate with external service",
			Status:  fiber.StatusBadGateway,
		})
	}

	currentTime := time.Now().Format("2006-01-02 03:04:05 PM")

	// Generate your actual response
	response := types.ApiResponse{
		Message: "Got redirect token Successfully!!!",
		Status:  fiber.StatusOK,
		Data: map[string]interface{}{
			"redirect_token": redirectToken,
		},
	}

	logger.Success("User token got successfully. Redirect token: " + redirectToken + " at " + currentTime)
	return c.Status(fiber.StatusOK).JSON(response)
}

func (h *AuthController) LogOut(c *fiber.Ctx) error {
	// Get the token from the Authorization header
	tokenStr := c.Get("Authorization")
	tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")

	// Clear the access and refresh cookies
	h.setSecureCookie(c, "access", "", -1)  // Expire immediately
	h.setSecureCookie(c, "refresh", "", -1) // Expire immediately

	response := types.ApiResponse{
		Message: "Logout successful",
		Status:  fiber.StatusOK,
		Data:    nil,
	}
	logger.Success("Logout successful")
	return c.Status(fiber.StatusOK).JSON(response)
}
