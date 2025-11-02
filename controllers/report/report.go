package report

import (
	"encoding/json"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"passport-booking/logger"
	bookingModel "passport-booking/models/booking"
)

type ReportController struct {
	db          *gorm.DB
	asyncLogger *logger.AsyncLogger
}

// NewReportController creates a new report controller instance
func NewReportController(db *gorm.DB, asyncLogger *logger.AsyncLogger) *ReportController {
	return &ReportController{
		db:          db,
		asyncLogger: asyncLogger,
	}
}

// SingleDeliveredReport handles the single delivered report endpoint
func (rc *ReportController) SingleDeliveredReport(c *fiber.Ctx) error {
	// Log the raw request body for debugging
	rawBody := string(c.Body())

	// Get order_id from request
	type RequestBody struct {
		OrderID string `json:"order_id"`
	}

	var req RequestBody

	// Check if body is empty
	if len(rawBody) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Empty request body",
			"message": "Request body is required",
			"status":  "failed",
		})
	}

	// Try alternative JSON parsing first
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		// If manual parsing fails, try Fiber's BodyParser
		if err2 := c.BodyParser(&req); err2 != nil {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{
				"error":            "Invalid request body",
				"message":          "Unprocessable Entity",
				"status":           "failed",
				"json_error":       err.Error(),
				"bodyparser_error": err2.Error(),
				"raw_body":         rawBody,
				"content_type":     c.Get("Content-Type"),
				"content_length":   len(rawBody),
			})
		}
	}

	// Validate required fields
	if req.OrderID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"message": "order_id is required and cannot be empty",
			"status":  "failed",
		})
	}

	// Search for booking events where barcode = order_id and status = delivered
	var bookingEvents []bookingModel.BookingEvent

	result := rc.db.Where("barcode = ? AND status = ?", req.OrderID, bookingModel.BookingStatusDelivered).
		Preload("User").
		Preload("DeliveryAddress").
		Find(&bookingEvents)

	if result.Error != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error occurred",
			"message": "Failed to fetch delivered booking events",
			"status":  "failed",
		})
	}

	// Format the response according to the requested specification
	if len(bookingEvents) > 0 {
		// Return the first found record as a single object
		event := bookingEvents[0]

		// Format the date as "year month day hour minute second"
		formattedDate := event.CreatedAt.Format("2006-01-02 15:04:05")

		// Check if barcode is nil and handle it
		var itemID string
		if event.Barcode != nil {
			itemID = *event.Barcode
		} else {
			itemID = ""
		}

		// Check if delivery branch code is nil and handle it
		var postingOffice string
		if event.DeliveryBranchCode != nil {
			postingOffice = *event.DeliveryBranchCode
		} else {
			postingOffice = ""
		}

		// Create response with proper field ordering
		type ResponseData struct {
			Posting       string `json:"Posting"`
			ItemID        string `json:"Item ID"`
			PostingOffice string `json:"Posting Office"`
			PostingDate   string `json:"Posting Date"`
		}

		type Response struct {
			Message string       `json:"message"`
			Status  int          `json:"status"`
			Data    ResponseData `json:"data"`
		}

		response := Response{
			Message: "Item Delivered successfully",
			Status:  200,
			Data: ResponseData{
				Posting:       "Delivered to Recipient",
				ItemID:        itemID,
				PostingOffice: postingOffice,
				PostingDate:   formattedDate,
			},
		}

		return c.JSON(response)
	}

	// If no records found
	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
		"message": "No delivered items found for this order ID",
		"status":  404,
		"data":    nil,
	})
}
