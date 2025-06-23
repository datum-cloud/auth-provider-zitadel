package signature

// NoopValidatePayload is a no-operation validator that always returns nil,
// effectively skipping signature validation. Useful for testing or when
// validation needs to be disabled.
func NoopValidatePayload(payload []byte, header string, signingKey string) error {
	return nil
}
