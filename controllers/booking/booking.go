package booking

import (
	"fmt"
	"os"
	"passport-booking/database"
	"passport-booking/logger"
	addressModel "passport-booking/models/address"
	bookingModel "passport-booking/models/booking"
	"passport-booking/models/otp"
	"passport-booking/models/slip_parser"
	"passport-booking/services/booking_event"
	otpService "passport-booking/services/otp"
	"passport-booking/types"
	bookingTypes "passport-booking/types/booking"
	"passport-booking/utils"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

// BookingController handles booking-related HTTP requests
type BookingController struct {
	DB             *gorm.DB
	Logger         *logger.AsyncLogger
	loggerInstance *logger.AsyncLogger
}

// NewBookingController creates a new booking controller
func NewBookingController(db *gorm.DB, asyncLogger *logger.AsyncLogger) *BookingController {
	return &BookingController{
		DB:             db,
		Logger:         asyncLogger,
		loggerInstance: asyncLogger,
	}
}

// Helper function to log API requests and responses
func (bc *BookingController) logAPIRequest(c *fiber.Ctx) {
	logEntry := utils.CreateSanitizedLogEntry(c)
	bc.loggerInstance.Log(logEntry)
}

// Helper function to send response and log in one call
func (bc *BookingController) sendResponseWithLog(c *fiber.Ctx, status int, response types.ApiResponse) error {
	result := c.Status(status).JSON(response)
	bc.logAPIRequest(c)
	return result
}

// booking list with pagination and filters
func (bc *BookingController) Index(c *fiber.Ctx) error {
	// Parse query parameters
	var req bookingTypes.BookingIndexRequest
	if err := c.QueryParser(&req); err != nil {
		logger.Error("Failed to parse query parameters", err)
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "Invalid query parameters",
			Data:    nil,
		})
	}

	// Validate request
	if err := req.Validate(); err != nil {
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: err.Error(),
			Data:    nil,
		})
	}

	// Get user authentication information
	claims, ok := c.Locals("user").(map[string]interface{})
	if !ok {
		return bc.sendResponseWithLog(c, fiber.StatusUnauthorized, types.ApiResponse{
			Message: "Invalid user claims",
			Status:  fiber.StatusUnauthorized,
			Data:    nil,
		})
	}

	userUUID, ok := claims["uuid"].(string)
	if !ok || userUUID == "" {
		return bc.sendResponseWithLog(c, fiber.StatusUnauthorized, types.ApiResponse{
			Message: "User UUID not found in token",
			Status:  fiber.StatusUnauthorized,
			Data:    nil,
		})
	}

	userInfo, err := utils.GetUserByUUID(userUUID)
	if err != nil {
		logger.Error("Error finding user by UUID", err)
		status := fiber.StatusInternalServerError
		msg := "Database error"
		if err.Error() == "user not found" {
			status = fiber.StatusUnauthorized
			msg = "User not found"
		}
		return bc.sendResponseWithLog(c, status, types.ApiResponse{
			Message: msg,
			Status:  status,
			Data:    nil,
		})
	}

	userID := uint(userInfo.ID)

	// Build query with filters and user restriction
	query := bc.DB.Model(&bookingModel.Booking{}).Preload("User").Preload("DeliveryAddress").Where("user_id = ?", userID)

	// Apply status filter
	if req.Status != "" {
		query = query.Where("status = ?", req.Status)
	}

	// Apply date range filters
	if req.FromDate != "" {
		fromTime, err := req.ParseFromDate()
		if err != nil {
			logger.Error("Failed to parse from_date", err)
			return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
				Status:  fiber.StatusBadRequest,
				Message: "Invalid from_date format",
				Data:    nil,
			})
		}
		query = query.Where("created_at >= ?", fromTime)
	}

	if req.ToDate != "" {
		toTime, err := req.ParseToDate()
		if err != nil {
			logger.Error("Failed to parse to_date", err)
			return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
				Status:  fiber.StatusBadRequest,
				Message: "Invalid to_date format",
				Data:    nil,
			})
		}
		query = query.Where("created_at <= ?", toTime)
	}

	// Get total count for pagination
	var total int64
	if err := query.Count(&total).Error; err != nil {
		logger.Error("Failed to count bookings", err)
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Failed to count bookings",
			Data:    nil,
		})
	}

	// Apply pagination
	var bookings []bookingModel.Booking
	if err := query.Offset(req.GetOffset()).Limit(req.GetLimit()).Order("created_at DESC").Find(&bookings).Error; err != nil {
		logger.Error("Failed to fetch bookings", err)
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Failed to fetch bookings",
			Data:    nil,
		})
	}

	// Calculate pagination metadata
	totalPages := int((total + int64(req.PerPage) - 1) / int64(req.PerPage))
	hasNext := req.Page < totalPages
	hasPrev := req.Page > 1

	// Prepare response
	response := bookingTypes.BookingIndexResponse{
		Data: bookings,
		Pagination: bookingTypes.PaginationResponse{
			CurrentPage: req.Page,
			PerPage:     req.PerPage,
			Total:       total,
			TotalPages:  totalPages,
			HasNext:     hasNext,
			HasPrev:     hasPrev,
		},
	}

	return bc.sendResponseWithLog(c, fiber.StatusOK, types.ApiResponse{
		Status:  fiber.StatusOK,
		Message: "Bookings fetched successfully",
		Data:    response,
	})
}

// Store creates a new booking with basic information (first step)
func (bc *BookingController) Store(c *fiber.Ctx) error {
	// Parse request body
	var req bookingTypes.BookingCreateRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Error("Failed to parse request body", err)
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "Invalid request body",
			Data:    nil,
		})
	}

	// Validate request using the validation method from types
	if err := req.Validate(); err != nil {
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: err.Error(),
			Data:    nil,
		})
	}

	claims, ok := c.Locals("user").(map[string]interface{})
	if !ok {
		return bc.sendResponseWithLog(c, fiber.StatusUnauthorized, types.ApiResponse{
			Message: "Invalid user claims",
			Status:  fiber.StatusUnauthorized,
			Data:    nil,
		})
	}

	userUUID, ok := claims["uuid"].(string)
	if !ok || userUUID == "" {
		return bc.sendResponseWithLog(c, fiber.StatusUnauthorized, types.ApiResponse{
			Message: "User UUID not found in token",
			Status:  fiber.StatusUnauthorized,
			Data:    nil,
		})
	}

	userInfo, err := utils.GetUserByUUID(userUUID)
	if err != nil {
		logger.Error("Error finding user by UUID", err)
		status := fiber.StatusInternalServerError
		msg := "Database error"
		if err.Error() == "user not found" {
			status = fiber.StatusUnauthorized
			msg = "User not found"
		}
		return bc.sendResponseWithLog(c, status, types.ApiResponse{
			Message: msg,
			Status:  status,
			Data:    nil,
		})
	}

	userPermission, ok := claims["permissions"].([]interface{})

	if !ok {
		return bc.sendResponseWithLog(c, fiber.StatusUnauthorized, types.ApiResponse{
			Message: "Invalid user permissions",
			Status:  fiber.StatusUnauthorized,
			Data:    nil,
		})
	}

	// Extract the role part (e.g., "customer" from "passport-booking.customer.full-permit")
	var UserBookingType string
	foundPermission := false
	for _, perm := range userPermission {
		permStr, ok := perm.(string)
		if !ok {
			continue
		}
		if strings.HasPrefix(permStr, "e-passport-delivery.") {
			parts := strings.Split(permStr, ".")
			if len(parts) >= 2 {
				prefix := parts[0]        // This will be "passport-booking"
				extractedRole := parts[1] // This will be "customer" or "agent"
				if prefix != "e-passport-delivery" {
					return bc.sendResponseWithLog(c, fiber.StatusForbidden, types.ApiResponse{
						Message: "Invalid permission prefix",
						Status:  fiber.StatusForbidden,
						Data:    nil,
					})
				}
				// Map the extracted role to BookingType constants
				if extractedRole == "customer" {
					UserBookingType = string(bookingModel.BookingTypeCustomer)
				} else if extractedRole == "agent" {
					UserBookingType = string(bookingModel.BookingTypeAgent)
				} else {
					return bc.sendResponseWithLog(c, fiber.StatusForbidden, types.ApiResponse{
						Message: "Invalid user role in permission",
						Status:  fiber.StatusForbidden,
						Data:    nil,
					})
				}
				logger.Info(fmt.Sprintf("User role extracted: %s, mapped to BookingType: %s from permission: %s", extractedRole, UserBookingType, permStr))
				foundPermission = true
				break
			}
		}
	}
	if !foundPermission {
		return bc.sendResponseWithLog(c, fiber.StatusForbidden, types.ApiResponse{
			Message: "No valid e-passport-delivery permission found",
			Status:  fiber.StatusForbidden,
			Data:    nil,
		})
	}

	userID := uint(userInfo.ID)
	var slipParserRequest slip_parser.SlipParserRequest
	err = database.DB.Where("request_id = ?", req.RequestID).First(&slipParserRequest).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
				Status:  fiber.StatusBadRequest,
				Message: "Invalid request_id: no matching slip parser request found",
				Data:    nil,
			})
		}
	} else if slipParserRequest.Status != "success" {
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "Invalid request_id: slip parser request was not successful",
			Data:    nil,
		})
	}

	// Check if booking with the same AppOrOrderID already exists
	var existingBooking bookingModel.Booking
	err = database.DB.Preload("User").Where("app_or_order_id = ?", slipParserRequest.AppOrOrderID).First(&existingBooking).Error

	if err == nil {
		// Booking already exists, return existing data
		logger.Info(fmt.Sprintf("Booking with AppOrOrderID %s already exists", slipParserRequest.AppOrOrderID))
		return bc.sendResponseWithLog(c, fiber.StatusOK, types.ApiResponse{
			Status:  fiber.StatusOK,
			Message: "Booking already exists",
			Data:    existingBooking,
		})
	} else if err != gorm.ErrRecordNotFound {
		// Some other database error occurred
		logger.Error("Database error while checking existing booking", err)
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Database error",
			Data:    nil,
		})
	}

	var booking bookingModel.Booking

	// Use DB.Transaction for automatic rollback on error
	err = database.DB.Transaction(func(tx *gorm.DB) error {

		// Create booking record with basic information only
		booking = bookingModel.Booking{
			UserID:                userID,
			AppOrOrderID:          slipParserRequest.AppOrOrderID,
			Name:                  slipParserRequest.Name,
			FatherName:            slipParserRequest.FatherName,
			MotherName:            slipParserRequest.MotherName,
			Phone:                 slipParserRequest.Phone,
			Address:               slipParserRequest.Address,
			EmergencyContactName:  &slipParserRequest.EmergencyContactName,
			EmergencyContactPhone: &slipParserRequest.EmergencyContactPhone,
			// i want to if +88 not have then add it otherwise keep the same
			DeliveryPhone: func() *string {
				if strings.HasPrefix(slipParserRequest.Phone, "+88") {
					return &slipParserRequest.Phone
				}

				phoneWithCountryCode := "+88" + slipParserRequest.Phone
				return &phoneWithCountryCode
			}(),

			Status:      bookingModel.BookingStatusInitial,
			BookingType: bookingModel.BookingType(UserBookingType),
			BookingDate: time.Now(),
			CreatedBy:   strconv.FormatUint(uint64(userID), 10),
			CreatedAt:   time.Now(),
			DeliveryAddress: &addressModel.Address{
				Division:       &req.Division,
				District:       &req.District,
				PoliceStation:  &req.PoliceStation,
				PostOffice:     &req.PostOffice,
				PostOfficeCode: &req.DeliveryBranchCode,
				StreetAddress:  &req.StreetAddress,
			},
			DeliveryBranchCode: &req.DeliveryBranchCode,
		}

		if err := tx.Create(&booking).Error; err != nil {
			logger.Error("Failed to create booking", err)
			return err
		}

		bookingStatusEvent := bookingModel.BookingStatusEvent{
			BookingID: booking.ID,
			Status:    booking.Status,
			CreatedBy: strconv.FormatUint(uint64(userID), 10),
		}

		if err := tx.Create(&bookingStatusEvent).Error; err != nil {
			logger.Error("Failed to create booking status event", err)
			return err
		}

		if err := booking_event.SnapshotBookingToEvent(tx, &booking, "created", strconv.FormatUint(uint64(userID), 10)); err != nil {
			logger.Error("Failed to write booking event (created)", err)
			return err
		}

		return nil
	})

	if err != nil {
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Failed to save booking",
			Data:    nil,
		})
	}

	// Log success
	logger.Success(fmt.Sprintf("Booking created successfully with ID: %d", booking.ID))

	// Load the complete booking data with relationships
	var createdBooking bookingModel.Booking
	err = database.DB.Preload("User").First(&createdBooking, booking.ID).Error
	if err != nil {
		logger.Error("Failed to load created booking data", err)
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Booking created but failed to retrieve complete data",
			Data:    nil,
		})
	}

	// Return success response with basic booking data
	return bc.sendResponseWithLog(c, fiber.StatusCreated, types.ApiResponse{
		Status:  fiber.StatusCreated,
		Message: "Booking created successfully",
		Data:    createdBooking,
	})
}

// StoreUpdate updates an existing booking with delivery and address information (second step)
func (bc *BookingController) Update(c *fiber.Ctx) error {
	var req bookingTypes.BookingStoreUpdateRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Error("Failed to parse request body", err)
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "Invalid request body",
			Data:    nil,
		})
	}

	// Validate request using the validation method from types
	if err := req.Validate(); err != nil {
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: err.Error(),
			Data:    nil,
		})
	}

	// Get booking ID from URL parameter
	bookingIDParam := req.ID
	bookingID, err := strconv.Atoi(fmt.Sprintf("%d", bookingIDParam))
	if err != nil || bookingID <= 0 {
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "Invalid booking ID",
			Data:    nil,
		})
	}

	// Get user information from token
	claims, ok := c.Locals("user").(map[string]interface{})
	if !ok {
		return bc.sendResponseWithLog(c, fiber.StatusUnauthorized, types.ApiResponse{
			Message: "Invalid user claims",
			Status:  fiber.StatusUnauthorized,
			Data:    nil,
		})
	}

	userUUID, ok := claims["uuid"].(string)
	if !ok || userUUID == "" {
		return bc.sendResponseWithLog(c, fiber.StatusUnauthorized, types.ApiResponse{
			Message: "User UUID not found in token",
			Status:  fiber.StatusUnauthorized,
			Data:    nil,
		})
	}

	userInfo, err := utils.GetUserByUUID(userUUID)
	if err != nil {
		logger.Error("Error finding user by UUID", err)
		status := fiber.StatusInternalServerError
		msg := "Database error"
		if err.Error() == "user not found" {
			status = fiber.StatusUnauthorized
			msg = "User not found"
		}
		return bc.sendResponseWithLog(c, status, types.ApiResponse{
			Message: msg,
			Status:  status,
			Data:    nil,
		})
	}

	userID := uint(userInfo.ID)

	// Find the existing booking
	var booking bookingModel.Booking
	if err := bc.DB.Preload("User").Preload("DeliveryAddress").First(&booking, bookingID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return bc.sendResponseWithLog(c, fiber.StatusNotFound, types.ApiResponse{
				Status:  fiber.StatusNotFound,
				Message: "Booking not found",
				Data:    nil,
			})
		}
		logger.Error("Failed to find booking", err)
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Database error",
			Data:    nil,
		})
	}

	// Check if the booking belongs to the current user
	if booking.UserID != userID {
		return bc.sendResponseWithLog(c, fiber.StatusForbidden, types.ApiResponse{
			Status:  fiber.StatusForbidden,
			Message: "You don't have permission to update this booking",
			Data:    nil,
		})
	}

	var address = booking.DeliveryAddress

	// Check if address already exists for this booking
	if address != nil {
		address.PoliceStation = &req.PoliceStation
		address.PostOffice = &req.PostOffice
		address.PostOfficeCode = &req.DeliveryBranchCode
		address.StreetAddress = &req.StreetAddress
		address.District = &req.District
		address.Division = &req.Division
		if err := bc.DB.Save(&address).Error; err != nil {
			logger.Error("Failed to update existing address", err)
			return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
				Status:  fiber.StatusInternalServerError,
				Message: "Failed to update address",
				Data:    nil,
			})
		}
		// Address updated successfully
		logger.Info(fmt.Sprintf("Existing address updated successfully for Booking ID: %d", booking.ID))
		return bc.sendResponseWithLog(c, fiber.StatusOK, types.ApiResponse{
			Status:  fiber.StatusOK,
			Message: "Booking delivery information updated successfully",
			Data:    booking,
		})
	}

	return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
		Status:  fiber.StatusInternalServerError,
		Message: "Address not found for this booking",
		Data:    nil,
	})

}

// show indivisual booking info
func (bc *BookingController) Show(c *fiber.Ctx) error {
	bookingIDParam := c.Params("id")
	bookingID, err := strconv.Atoi(bookingIDParam)
	if err != nil || bookingID <= 0 {
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "Invalid booking ID",
			Data:    nil,
		})
	}

	var booking bookingModel.Booking
	if err := bc.DB.Preload("User").Preload("DeliveryAddress").First(&booking, bookingID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return bc.sendResponseWithLog(c, fiber.StatusNotFound, types.ApiResponse{
				Status:  fiber.StatusNotFound,
				Message: "Booking not found",
				Data:    nil,
			})
		}
		logger.Error("Failed to fetch booking", err)
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Failed to fetch booking",
			Data:    nil,
		})
	}

	return bc.sendResponseWithLog(c, fiber.StatusOK, types.ApiResponse{
		Status:  fiber.StatusOK,
		Message: "Booking fetched successfully",
		Data:    booking,
	})
}

// booking status event history
func (bc *BookingController) GetBookingStatusEvent(c *fiber.Ctx) error {
	bookingIDParam := c.Params("id")
	bookingID, err := strconv.Atoi(bookingIDParam)
	if err != nil || bookingID <= 0 {
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "Invalid booking ID",
			Data:    nil,
		})
	}
	var statusEvents []bookingModel.BookingStatusEvent
	if err := bc.DB.Preload("Booking").Preload("Booking.User").Preload("Booking.DeliveryAddress").Where("booking_id = ?", bookingID).Order("created_at DESC").Find(&statusEvents).Error; err != nil {
		logger.Error("Failed to fetch booking status events", err)
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Failed to fetch booking status events",
			Data:    nil,
		})
	}
	return bc.sendResponseWithLog(c, fiber.StatusOK, types.ApiResponse{
		Status:  fiber.StatusOK,
		Message: "Booking status events fetched successfully",
		Data:    statusEvents,
	})
}

// UpdateDeliveryPhone updates the delivery phone for a booking
func (bc *BookingController) DeliveryPhoneSendOtp(c *fiber.Ctx) error {

	var req bookingTypes.DeliveryPhoneSendOtpRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Error("Failed to parse request body", err)
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "Invalid request body",
			Data:    nil,
		})
	}

	// Validate request using the validation method from types
	if err := req.Validate(); err != nil {
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: err.Error(),
			Data:    nil,
		})
	}

	// Get user authentication information
	claims, ok := c.Locals("user").(map[string]interface{})
	if !ok {
		return bc.sendResponseWithLog(c, fiber.StatusUnauthorized, types.ApiResponse{
			Message: "Invalid user claims",
			Status:  fiber.StatusUnauthorized,
			Data:    nil,
		})
	}

	userUUID, ok := claims["uuid"].(string)
	if !ok || userUUID == "" {
		return bc.sendResponseWithLog(c, fiber.StatusUnauthorized, types.ApiResponse{
			Message: "User UUID not found in token",
			Status:  fiber.StatusUnauthorized,
			Data:    nil,
		})
	}

	userInfo, err := utils.GetUserByUUID(userUUID)
	if err != nil {
		logger.Error("Error finding user by UUID", err)
		status := fiber.StatusInternalServerError
		msg := "Database error"
		if err.Error() == "user not found" {
			status = fiber.StatusUnauthorized
			msg = "User not found"
		}
		return bc.sendResponseWithLog(c, status, types.ApiResponse{
			Message: msg,
			Status:  status,
			Data:    nil,
		})
	}

	userID := uint(userInfo.ID)

	// Find the booking
	var booking bookingModel.Booking
	if err := bc.DB.First(&booking, req.BookingID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return bc.sendResponseWithLog(c, fiber.StatusNotFound, types.ApiResponse{
				Status:  fiber.StatusNotFound,
				Message: "Booking not found",
				Data:    nil,
			})
		}
		logger.Error("Failed to find booking", err)
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Internal server error",
			Data:    nil,
		})
	}

	// Check if the booking belongs to the current user
	if booking.UserID != userID {
		return bc.sendResponseWithLog(c, fiber.StatusForbidden, types.ApiResponse{
			Status:  fiber.StatusForbidden,
			Message: "You don't have permission to update this booking",
			Data:    nil,
		})
	}

	if booking.DeliveryPhone == nil {
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "No delivery phone found for this booking",
			Data:    nil,
		})
	}

	booking.DeliveryPhoneAppliedVerified = false // Reset verification status

	if err := bc.DB.Save(&booking).Error; err != nil {
		logger.Error("Failed to update delivery phone", err)
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Failed to update delivery phone",
			Data:    nil,
		})
	}

	if err := booking_event.SnapshotBookingToEvent(bc.DB, &booking, "delivery_phone_send_otp", strconv.FormatUint(uint64(booking.UserID), 10)); err != nil {
		logger.Error("Failed to write booking event (delivery_phone_send_otp)", err)
	}

	// Send OTP to the new delivery phone
	otpSvc := otpService.NewOTPService(bc.DB)
	otpRecord, err := otpSvc.SendOTPWithBookingID(*booking.DeliveryPhone, req.Purpose, &req.BookingID)
	if err != nil {
		logger.Error("Failed to send OTP to delivery phone", err)

		// Check if it's a blocking error that should be returned as error response
		errMsg := err.Error()
		if errMsg == "OTP requests are blocked permanently due to too many failed attempts" ||
			(len(errMsg) > 20 && errMsg[:20] == "OTP requests are blocked until") {
			return bc.sendResponseWithLog(c, fiber.StatusTooManyRequests, types.ApiResponse{
				Status:  fiber.StatusTooManyRequests,
				Message: err.Error(),
				Data:    nil,
			})
		}

		// For other OTP errors, return error response instead of continuing
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Failed to send OTP to delivery phone",
			Data: map[string]interface{}{
				"booking":   booking,
				"otp_error": err.Error(),
			},
		})
	} else {
		logger.Success(fmt.Sprintf("OTP sent to delivery phone %s for booking ID: %d", booking.Phone, req.BookingID))
	}

	responseData := map[string]interface{}{
		"booking": booking,
	}
	_env := os.Getenv("APP_ENV")
	if otpRecord != nil {
		responseData["otp_info"] = map[string]interface{}{
			"otp_id":     otpRecord.ID,
			"expires_at": otpRecord.ExpiresAt,
			"phone":      booking.DeliveryPhone,
		}
	}

	if _env != "production" && otpRecord != nil {
		// Include OTP code in response for non-production environments
		responseData["otp_info"].(map[string]interface{})["otp_code"] = otpRecord.OTPCode
	}

	return bc.sendResponseWithLog(c, fiber.StatusOK, types.ApiResponse{
		Status:  fiber.StatusOK,
		Message: "OTP sent successfully",
		Data:    responseData,
	})
}

// VerifyDeliveryPhone verifies the delivery phone OTP and marks it as verified
func (bc *BookingController) VerifyDeliveryPhone(c *fiber.Ctx) error {
	var req bookingTypes.VerifyDeliveryPhoneRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Error("Failed to parse request body", err)
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "Invalid request body",
			Data:    nil,
		})
	}

	// Validate request using the validation method from types
	if err := req.Validate(); err != nil {
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: err.Error(),
			Data:    nil,
		})
	}

	// Find the booking
	var booking bookingModel.Booking
	if err := bc.DB.First(&booking, req.BookingID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return bc.sendResponseWithLog(c, fiber.StatusNotFound, types.ApiResponse{
				Status:  fiber.StatusNotFound,
				Message: "Booking not found",
				Data:    nil,
			})
		}
		logger.Error("Failed to find booking", err)
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Internal server error",
			Data:    nil,
		})
	}

	// Check if booking has a delivery phone set
	if booking.DeliveryPhone == nil {
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "No delivery phone found for this booking",
			Data:    nil,
		})
	}

	if booking.DeliveryPhoneAppliedVerified {
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "Delivery phone is already verified",
			Data:    nil,
		})
	}

	// Verify OTP using OTP service
	otpSvc := otpService.NewOTPService(bc.DB)
	isValid, otpRecord, err := otpSvc.VerifyOTPWithDetails(*booking.DeliveryPhone, req.OTPCode, req.Purpose)
	if err != nil {
		logger.Error("Failed to verify OTP", err)

		// If we have an OTP record, we can provide more detailed error information
		if otpRecord != nil {
			remainingAttempts := otpRecord.MaxRetries - otpRecord.RetryCount
			isBlocked := otpRecord.IsCurrentlyBlocked()
			isExpired := otpRecord.IsExpired()

			// Handle OTP expiration separately
			if isExpired {
				return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
					Status:  fiber.StatusBadRequest,
					Message: "OTP has expired. Please request a new OTP",
					Data: map[string]interface{}{
						"error":              "OTP_EXPIRED",
						"expired_at":         otpRecord.ExpiresAt,
						"is_expired":         true,
						"is_blocked":         isBlocked,
						"remaining_attempts": remainingAttempts,
						"success":            false,
					},
				})
			}

			// Handle blocked OTP separately
			if isBlocked {
				return bc.sendResponseWithLog(c, fiber.StatusTooManyRequests, types.ApiResponse{
					Status:  fiber.StatusTooManyRequests,
					Message: err.Error(), // This will contain the detailed blocked message
					Data: map[string]interface{}{
						"error":              "OTP_BLOCKED",
						"is_blocked":         true,
						"blocked_until":      otpRecord.BlockedUntil,
						"remaining_attempts": remainingAttempts,
						"success":            false,
					},
				})
			}

			// Handle other OTP verification errors (like wrong OTP)
			return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
				Status:  fiber.StatusBadRequest,
				Message: err.Error(), // This will contain the detailed error message with attempts
				Data: map[string]interface{}{
					"error":              "OTP_INVALID",
					"remaining_attempts": remainingAttempts,
					"is_blocked":         isBlocked,
					"is_expired":         isExpired,
					"success":            false,
				},
			})
		}

		// Fallback for other errors
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: err.Error(), // Show the actual error message instead of generic
			Data:    nil,
		})
	}

	if !isValid {
		// This case should rarely happen now since we handle specific errors above
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "Invalid OTP",
			Data:    nil,
		})
	}

	// Encrypt OTP data for storage
	var deliveryPhoneAppliedOTPEncrypted string

	if otpRecord != nil {
		// Encrypt the delivered OTP (the OTP code that was verified)
		encryptedDeliveryPhoneAppliedOTP, err := utils.EncryptData(otpRecord.OTPCode)
		if err != nil {
			logger.Error("Failed to encrypt delivered OTP", err)
		} else {
			deliveryPhoneAppliedOTPEncrypted = encryptedDeliveryPhoneAppliedOTP
		}
	}

	// Mark delivery phone as verified and store encrypted OTPs
	booking.DeliveryPhoneAppliedVerified = true
	booking.DeliveryPhoneAppliedOTPEncrypted = &deliveryPhoneAppliedOTPEncrypted
	booking.Status = bookingModel.BookingStatusPreBooked

	// Save the updated booking
	if err := bc.DB.Save(&booking).Error; err != nil {
		logger.Error("Failed to update delivery phone verification status", err)
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Failed to update verification status",
			Data:    nil,
		})
	}

	// Get user authentication information for booking status event
	claims, ok := c.Locals("user").(map[string]interface{})
	if !ok {
		return bc.sendResponseWithLog(c, fiber.StatusUnauthorized, types.ApiResponse{
			Message: "Invalid user claims",
			Status:  fiber.StatusUnauthorized,
			Data:    nil,
		})
	}

	userUUID, ok := claims["uuid"].(string)
	if !ok || userUUID == "" {
		return bc.sendResponseWithLog(c, fiber.StatusUnauthorized, types.ApiResponse{
			Message: "User UUID not found in token",
			Status:  fiber.StatusUnauthorized,
			Data:    nil,
		})
	}

	userInfo, err := utils.GetUserByUUID(userUUID)
	if err != nil {
		logger.Error("Error finding user by UUID", err)
		status := fiber.StatusInternalServerError
		msg := "Database error"
		if err.Error() == "user not found" {
			status = fiber.StatusUnauthorized
			msg = "User not found"
		}
		return bc.sendResponseWithLog(c, status, types.ApiResponse{
			Message: msg,
			Status:  status,
			Data:    nil,
		})
	}

	userID := uint(userInfo.ID)

	bookingStatusEvent := bookingModel.BookingStatusEvent{
		BookingID: booking.ID,
		Status:    booking.Status,
		CreatedBy: strconv.FormatUint(uint64(userID), 10),
	}

	if err := bc.DB.Create(&bookingStatusEvent).Error; err != nil {
		logger.Error("Failed to create booking status event", err)
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Failed to create booking status event",
			Data:    nil,
		})
	}

	if err := booking_event.SnapshotBookingToEvent(bc.DB, &booking, "phone_applied_verified", strconv.FormatUint(uint64(booking.UserID), 10)); err != nil {
		logger.Error("Failed to write booking event (phone_applied_verified)", err)
	}

	logger.Success(fmt.Sprintf("Delivery phone verified for booking ID: %d", booking.ID))

	responseData := map[string]interface{}{
		"booking":  booking,
		"verified": true,
	}

	return bc.sendResponseWithLog(c, fiber.StatusOK, types.ApiResponse{
		Status:  fiber.StatusOK,
		Message: "Delivery phone verified successfully",
		Data:    responseData,
	})
}

// GetOTPRetryInfo returns retry information for delivery phone OTP
func (bc *BookingController) GetOTPRetryInfo(c *fiber.Ctx) error {
	var req bookingTypes.GetOTPRetryInfoRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Error("Failed to parse request body", err)
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "Invalid request body",
			Data:    nil,
		})
	}

	// Validate request using the validation method from types
	if err := req.Validate(); err != nil {
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: err.Error(),
			Data:    nil,
		})
	}

	// Find the booking to validate booking_id and phone match
	var booking bookingModel.Booking
	if err := bc.DB.First(&booking, req.BookingID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return bc.sendResponseWithLog(c, fiber.StatusNotFound, types.ApiResponse{
				Status:  fiber.StatusNotFound,
				Message: "Booking not found",
				Data:    nil,
			})
		}
		logger.Error("Failed to find booking", err)
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Internal server error",
			Data:    nil,
		})
	}

	// Check if delivery phone exists in the booking
	if booking.DeliveryPhone == nil {
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "No delivery phone found for this booking",
			Data:    nil,
		})
	}

	if *booking.DeliveryPhone == "" {
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "No delivery phone found for this booking",
			Data:    nil,
		})
	}

	// Get retry information from OTP service with the specified purpose
	otpSvc := otpService.NewOTPService(bc.DB)
	retryInfo, err := otpSvc.GetOTPRetryInfo(*booking.DeliveryPhone, req.Purpose)
	if err != nil {
		logger.Error("Failed to get OTP retry info", err)
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Internal server error",
			Data:    nil,
		})
	}

	return bc.sendResponseWithLog(c, fiber.StatusOK, types.ApiResponse{
		Status:  fiber.StatusOK,
		Message: "OTP retry information retrieved successfully",
		Data: map[string]interface{}{
			"retry_info": retryInfo,
			"phone":      booking.DeliveryPhone,
			"purpose":    req.Purpose,
			"booking_id": req.BookingID,
		},
	})
}

// ResendOTP resends OTP for delivery phone verification
func (bc *BookingController) ResendOTP(c *fiber.Ctx) error {
	var req bookingTypes.ResendOTPRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Error("Failed to parse request body", err)
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: "Invalid request body",
			Data:    nil,
		})
	}
	// Validate request using the validation method from types
	if err := req.Validate(); err != nil {
		return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
			Status:  fiber.StatusBadRequest,
			Message: err.Error(),
			Data:    nil,
		})
	}

	// Find the booking to verify the phone number
	var booking bookingModel.Booking
	if err := bc.DB.First(&booking, req.BookingID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return bc.sendResponseWithLog(c, fiber.StatusNotFound, types.ApiResponse{
				Status:  fiber.StatusNotFound,
				Message: "Booking not found",
				Data:    nil,
			})
		}
		logger.Error("Failed to find booking", err)
		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Internal server error",
			Data:    nil,
		})
	}

	// Validate based on the OTP purpose
	switch req.Purpose {
	case otp.OTPPurposeDeliveryApplyPhone:
		if booking.DeliveryPhone == nil || *booking.DeliveryPhone == "" {
			return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
				Status:  fiber.StatusBadRequest,
				Message: "No delivery phone found for this booking",
				Data:    nil,
			})
		}
		// Check if already verified for apply purpose
		if booking.DeliveryPhoneAppliedVerified {
			return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
				Status:  fiber.StatusBadRequest,
				Message: "Delivery Apply phone is already verified",
				Data:    nil,
			})
		}
	case otp.OTPPurposeDeliveryConfirmPhone:
		if booking.DeliveryPhone == nil || *booking.DeliveryPhone == "" {
			return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
				Status:  fiber.StatusBadRequest,
				Message: "No delivery phone found for this booking",
				Data:    nil,
			})
		}
		// Check if already verified for confirm purpose
		if booking.DeliveryPhoneAppliedVerified {
			return bc.sendResponseWithLog(c, fiber.StatusBadRequest, types.ApiResponse{
				Status:  fiber.StatusBadRequest,
				Message: "Delivery Confirm phone is already verified",
				Data:    nil,
			})
		}
	}

	// Resend OTP using OTP service (will update existing unused OTP or create new one)
	otpSvc := otpService.NewOTPService(bc.DB)
	otpRecord, err := otpSvc.ResendOTPWithBookingID(*booking.DeliveryPhone, req.Purpose, &req.BookingID)
	if err != nil {
		logger.Error("Failed to send OTP", err)

		// Check if it's a blocking error
		errMsg := err.Error()
		if errMsg == "OTP requests are blocked permanently due to too many failed attempts" ||
			len(errMsg) > 20 && errMsg[:20] == "OTP requests are blocked until" {
			return bc.sendResponseWithLog(c, fiber.StatusTooManyRequests, types.ApiResponse{
				Status:  fiber.StatusTooManyRequests,
				Message: err.Error(),
				Data:    nil,
			})
		}

		return bc.sendResponseWithLog(c, fiber.StatusInternalServerError, types.ApiResponse{
			Status:  fiber.StatusInternalServerError,
			Message: "Failed to send OTP",
			Data:    nil,
		})
	}

	logger.Success(fmt.Sprintf("OTP resent to phone %s for booking ID: %d with purpose: %s", *booking.DeliveryPhone, req.BookingID, req.Purpose))

	return bc.sendResponseWithLog(c, fiber.StatusOK, types.ApiResponse{
		Status:  fiber.StatusOK,
		Message: "OTP resent successfully",
		Data: map[string]interface{}{
			"otp_id":     otpRecord.ID,
			"expires_at": otpRecord.ExpiresAt,
			"phone":      booking.DeliveryPhone,
			"purpose":    req.Purpose,
		},
	})
}
