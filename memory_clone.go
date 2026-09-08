package auth

func cloneUser(user User) User {
	user.WebAuthnID = append([]byte(nil), user.WebAuthnID...)
	return user
}

func clonePasskey(credential PasskeyCredential) PasskeyCredential {
	credential.ID = append([]byte(nil), credential.ID...)
	credential.PublicKey = append([]byte(nil), credential.PublicKey...)
	credential.Transports = append([]string(nil), credential.Transports...)
	credential.AAGUID = append([]byte(nil), credential.AAGUID...)
	return credential
}

func cloneRecovery(codes []RecoveryCode) []RecoveryCode {
	result := make([]RecoveryCode, len(codes))
	for i := range codes {
		result[i] = codes[i]
		result[i].Proof = append([]byte(nil), codes[i].Proof...)
	}
	return result
}
