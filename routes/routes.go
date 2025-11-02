package routes

import (
	"os"
	"passport-booking/constants"
	"passport-booking/controllers/auth"
	"passport-booking/controllers/bag"
	"passport-booking/controllers/booking"
	"passport-booking/controllers/delivery"
	"passport-booking/controllers/passport_percel"
	"passport-booking/controllers/report"
	"passport-booking/controllers/user"
	httpServices "passport-booking/httpServices/sso"
	"passport-booking/logger"
	"passport-booking/middleware"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

func SetupRoutes(app *fiber.App, db *gorm.DB) {
	//ssoClient := httpServices.NewClient(os.Getenv("SSO_BASE_URL"))
	dmsClient := httpServices.NewClient(os.Getenv("DMS_BASE_URL"))
	asyncLogger := logger.NewAsyncLogger(db)
	authController := auth.NewAuthController(dmsClient, db, asyncLogger)
	bookingController := booking.NewBookingController(db, asyncLogger)
	bagController := bag.NewBagController(db, asyncLogger)
	deliveryController := delivery.NewDeliveryController(db, asyncLogger)
	regionalPassportOfficeController := passport_percel.NewRegionalPassportOfficeController(db, asyncLogger)
	parcelBookingController := passport_percel.NewParcelBookingController(db, asyncLogger)
	reportController := report.NewReportController(db, asyncLogger)

	// Start the async logger processing goroutine
	go asyncLogger.ProcessLog()

	// Index route
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("index", fiber.Map{
			"title": "Home",
		})
	})

	/*=============================================================================
	| Public Routes
	===============================================================================*/
	api := app.Group("/api")
	api.Post("/get-service-token", authController.GetServiceToken)
	api.Post("/login", authController.Login)
	api.Post("/register", authController.Register)

	/*=============================================================================
	Bag api routes
	===============================================================================*/
	bagGroup := api.Group("/bag")

	bagGroup.Get("/branch-list", middleware.RequirePermissions(constants.PermSuperAdminFull), bag.GetBranchList)
	bagGroup.Get("/operator-list", middleware.RequirePermissions(constants.PermSuperAdminFull), bag.GetOperatorList)
	bagGroup.Post("/branch-mapping", middleware.RequirePermissions(constants.PermSuperAdminFull), bag.CreateBranchMapping)
	bagGroup.Post("/create", middleware.RequirePermissions(constants.PermOperatorFull), bag.CreateBag)
	bagGroup.Post("/item_add", middleware.RequirePermissions(constants.PermOperatorFull), bag.AddItemToBag)
	bagGroup.Post("/close", middleware.RequirePermissions(constants.PermOperatorFull), bag.CloseBag)
	bagGroup.Get("/booking_list", middleware.RequirePermissions(
		constants.PermOperatorFull,
		constants.PermAgentHasFull,
	), bagController.Index)

	bagGroup.Post("/receive", middleware.RequirePermissions(
		constants.PermPostmanFull,
		constants.PermPostOfficeFull,
	), bagController.ReceiveBag)

	/*=============================================================================
	| Protected Routes
	===============================================================================*/
	//auth := api.Group("/auth").Use(middleware.RequireAnyPermission())
	//auth.Post("/register", authController.Register)
	//auth.Get("/profile", user.GetUserInfo)
	//auth.Post("/logout", authController.LogOut)
	//
	authGroup := api.Group("/auth").Use(middleware.RequireAnyPermission())
	authGroup.Post("/register", authController.Register)
	authGroup.Get("/profile", user.GetUserInfo)
	authGroup.Post("/logout", authController.LogOut)

	/*=============================================================================
	| Booking Routes
	===============================================================================*/
	bookingGroup := api.Group("/booking")

	bookingGroup.Post("/create", middleware.RequirePermissions(
		constants.PermAgentHasFull,
		constants.PermCustomerFull,
	), bookingController.Store)

	bookingGroup.Put("/update", middleware.RequirePermissions(
		constants.PermAgentHasFull,
		constants.PermCustomerFull,
	), bookingController.Update)

	bookingGroup.Get("/list", middleware.RequirePermissions(
		constants.PermAgentHasFull,
		constants.PermCustomerFull,
		constants.PermOperatorFull,
	), bookingController.Index)
	bookingGroup.Get("/details/:id", middleware.RequirePermissions(
		constants.PermAgentHasFull,
		constants.PermCustomerFull,
	), bookingController.Show)

	bookingGroup.Post("/parse-passport-slip", middleware.RequirePermissions(
		constants.PermAgentHasFull,
		constants.PermCustomerFull,
	), bookingController.ParsePassportSlip)

	bookingGroup.Get("/get-booking-status-event/:id", middleware.RequirePermissions(
		constants.PermAgentHasFull,
		constants.PermCustomerFull,
	), bookingController.GetBookingStatusEvent)

	/*=============================================================================
	| OTP Routes for Booking
	===============================================================================*/

	// Delivery phone management routes
	bookingGroup.Post("/delivery-phone-send-otp", middleware.RequirePermissions(
		constants.PermAgentHasFull,
		constants.PermCustomerFull,
	), bookingController.DeliveryPhoneSendOtp)

	bookingGroup.Post("/verify-delivery-phone", middleware.RequirePermissions(
		constants.PermAgentHasFull,
		constants.PermCustomerFull,
	), bookingController.VerifyDeliveryPhone)

	bookingGroup.Post("/otp-retry-info", middleware.RequirePermissions(
		constants.PermAgentHasFull,
		constants.PermCustomerFull,
	), bookingController.GetOTPRetryInfo)

	bookingGroup.Post("/resend-otp", middleware.RequirePermissions(
		constants.PermAgentHasFull,
		constants.PermCustomerFull,
	), bookingController.ResendOTP)

	/*=============================================================================
	| OTP Routes for Delivery Confirmation
	===============================================================================*/
	deliveredGroup := api.Group("/delivered")

	deliveredGroup.Post("/send-otp", middleware.RequirePermissions(
		constants.PermPostmanFull,
	), deliveryController.DeliveryConfirmationSendOtp)

	deliveredGroup.Post("/verify-otp", middleware.RequirePermissions(
		constants.PermPostmanFull,
	), deliveryController.DeliveryConfirmationVerifyOtp)

	deliveredGroup.Post("/verify-application-id", middleware.RequirePermissions(
		constants.PermPostmanFull,
	), deliveryController.VerifyApplicationID)

	deliveredGroup.Post("/upload-photo", middleware.RequirePermissions(
		constants.PermPostmanFull,
	), deliveryController.UploadDeliveryPhoto)

	deliveredGroup.Post("/item-delivery", middleware.RequirePermissions(
		constants.PermPostmanFull,
	), deliveryController.ItemDelivery)

	deliveredGroup.Post("/itemdetails", middleware.RequirePermissions(
		constants.PermPostmanFull,
	), deliveryController.ItemDetails)

	deliveredGroup.Post("/receive", middleware.RequirePermissions(
		constants.PermPostmanFull,
	), deliveryController.ReceiveItem)

	/*=============================================================================
	| Regional Passport Office Routes
	===============================================================================*/
	regionalOfficeGroup := api.Group("/regional-passport-office")

	// Get list of all regional passport offices (public route)
	regionalOfficeGroup.Get("/list", middleware.RequirePermissions(
		constants.PermParcelOperatorFull,
	), regionalPassportOfficeController.GetRegionalPassportOffices)

	regionalOfficeGroup.Post("/store", middleware.RequirePermissions(
		constants.PermSuperAdminFull,
	), regionalPassportOfficeController.StoreRegionalPassportOffice)

	/*=============================================================================
	| Parcel Booking Routes
	===============================================================================*/
	parcelBookingGroup := api.Group("/parcelbooking")

	parcelBookingGroup.Post("/store", middleware.RequirePermissions(
		constants.PermParcelOperatorFull,
	), parcelBookingController.Store)

	// Parcel booking pending status route
	parcelBookingGroup.Post("/pending", middleware.RequirePermissions(
		constants.PermParcelOperatorFull,
	), parcelBookingController.StorePendingBooking)

	// Parcel booking submit route
	parcelBookingGroup.Post("/submit", middleware.RequirePermissions(
		constants.PermParcelOperatorFull,
	), parcelBookingController.StoreSubmit)

	parcelBookingGroup.Get("/list", middleware.RequirePermissions(
		constants.PermParcelOperatorFull,
	), parcelBookingController.Index)

	/*=============================================================================
	| Report Routes
	===============================================================================*/

	reportGroup := api.Group("/report")

	// Add report routes here
	reportGroup.Post("/single-delivered", middleware.RequirePermissions(
		constants.PermPostmanFull,
	), reportController.SingleDeliveredReport)
}
