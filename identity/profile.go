package identity

// define certificate template type 
type Profile struct {
	Type IdentityType
	CommonName string
	DNSName []string
}