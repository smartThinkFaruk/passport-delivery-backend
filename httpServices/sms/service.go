package sms

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"passport-booking/logger"
	"time"
)

// SMSService handles SMS operations
type SMSService struct {
	client    *http.Client
	apiURL    string
	authToken string
}

// SMSRequest represents the SMS request payload
type SMSRequest struct {
	SMSBody     string `json:"sms_body"`
	PhoneNumber string `json:"phone_number"`
}

// SMSResponse represents the SMS API response
type SMSResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// NewSMSService creates a new SMS service
func NewSMSService() *SMSService {
	apiURL := os.Getenv("EKDAK_BACKEND_API_URL")
	if apiURL == "" {
		apiURL = "https://ekdak.com/message-broker/send-sms/" // Default URL
	}

	authToken := os.Getenv("SMS_AUTH_TOKEN")
	if authToken == "" {
		authToken = "Token 8d3690ef76134d9abd78f9cbde655dd46446a032" // Default token
	}

	return &SMSService{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiURL:    apiURL,
		authToken: authToken,
	}
}

// SendSMS sends an SMS using the external API
func (s *SMSService) SendSMS(phoneNumber, message string) (*SMSResponse, error) {
	// Prepare the request payload
	smsReq := SMSRequest{
		SMSBody:     message,
		PhoneNumber: phoneNumber,
	}

	// Convert to JSON
	jsonData, err := json.Marshal(smsReq)
	if err != nil {
		logger.Error("Failed to marshal SMS request", err)
		return nil, fmt.Errorf("failed to marshal SMS request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", s.apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		logger.Error("Failed to create HTTP request", err)
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", s.authToken)

	// Make the request
	resp, err := s.client.Do(req)
	if err != nil {
		logger.Error("Failed to send SMS request", err)
		return nil, fmt.Errorf("failed to send SMS request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Failed to read response body", err)
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse response
	var smsResp SMSResponse
	if err := json.Unmarshal(body, &smsResp); err != nil {
		logger.Error("Failed to unmarshal response", err)
		// If JSON parsing fails, create a response based on HTTP status
		smsResp = SMSResponse{
			Success: resp.StatusCode >= 200 && resp.StatusCode < 300,
			Message: string(body),
		}
	}

	// Check HTTP status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Error(fmt.Sprintf("SMS API returned error status: %d", resp.StatusCode), nil)
		return &smsResp, fmt.Errorf("SMS API returned error status: %d, message: %s", resp.StatusCode, smsResp.Message)
	}

	logger.Info(fmt.Sprintf("SMS sent successfully to %s", phoneNumber))
	return &smsResp, nil
}

// SendOTP sends an OTP SMS to the specified phone number
func (s *SMSService) SendOTP(phoneNumber, otpCode string) error {
	message := fmt.Sprintf("Your OTP code is: %s. This code will expire in 5 minutes. Please do not share this code with anyone.", otpCode)

	_, err := s.SendSMS(phoneNumber, message)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to send OTP to %s", phoneNumber), err)
		return fmt.Errorf("failed to send OTP SMS: %w", err)
	}

	logger.Info(fmt.Sprintf("OTP sent successfully to %s", phoneNumber))
	return nil
}

// SendDeliveryNotification sends a delivery notification SMS
func (s *SMSService) SendDeliveryNotification(phoneNumber, bookingID string) error {
	message := fmt.Sprintf("Your passport delivery is confirmed for booking ID: %s. Our delivery partner will contact you soon.", bookingID)

	_, err := s.SendSMS(phoneNumber, message)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to send delivery notification to %s", phoneNumber), err)
		return fmt.Errorf("failed to send delivery notification SMS: %w", err)
	}

	logger.Info(fmt.Sprintf("Delivery notification sent successfully to %s", phoneNumber))
	return nil
}
