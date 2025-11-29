package constants

// Organization permissions
const (
	// Admin permissions
	PermSuperAdminFull     = "e-passport-delivery.super-admin.full-permit"
	PermEkdakDPMGFull      = "ekdak.dpmg.full-permit"
	PermPassportDPMGFull   = "e-passport-delivery.dpmg.full-permit"
	PermPostOfficeFull     = "e-passport-delivery.postmaster.full-permit"
	PermOrgSupervisorFull  = "e-passport-delivery.supervisor.full-permit"
	PermOperatorFull       = "e-passport-delivery.operator.full-permit"
	PermParcelOperatorFull = "e-passport-delivery.parcel-operator.full-permit"
	PermAgentHasFull       = "e-passport-delivery.agent.full-permit"
	PermPostmanFull        = "e-passport-delivery.postman.full-permit"
	PermCustomerFull       = "e-passport-delivery.customer.full-permit"

	// Special permissions
	PermAny = "any"
)

// Permission groups for convenience
var (
	OrganizationAdminPermissions = []string{
		PermEkdakDPMGFull,
		PermPassportDPMGFull,
		PermPostOfficeFull,
	}
)
