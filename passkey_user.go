package auth

import (
	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
)

type passkeyUser struct {
	user        User
	credentials []PasskeyCredential
}

func (u passkeyUser) WebAuthnID() []byte          { return u.user.WebAuthnID }
func (u passkeyUser) WebAuthnName() string        { return u.user.Identifier }
func (u passkeyUser) WebAuthnDisplayName() string { return u.user.DisplayName }
func (u passkeyUser) WebAuthnIcon() string        { return "" }

func (u passkeyUser) WebAuthnCredentials() []webauthnlib.Credential {
	result := make([]webauthnlib.Credential, len(u.credentials))
	for i := range u.credentials {
		result[i] = toWebAuthnCredential(u.credentials[i])
	}
	return result
}

func toWebAuthnCredential(value PasskeyCredential) webauthnlib.Credential {
	transports := make([]protocol.AuthenticatorTransport, len(value.Transports))
	for i := range value.Transports {
		transports[i] = protocol.AuthenticatorTransport(value.Transports[i])
	}
	return webauthnlib.Credential{
		ID: value.ID, PublicKey: value.PublicKey, AttestationType: value.AttestationType, Transport: transports,
		Flags:         webauthnlib.CredentialFlags{UserPresent: value.UserPresent, UserVerified: value.UserVerified, BackupEligible: value.BackupEligible, BackupState: value.BackupState},
		Authenticator: webauthnlib.Authenticator{AAGUID: value.AAGUID, SignCount: value.SignCount, CloneWarning: value.CloneWarning, Attachment: protocol.AuthenticatorAttachment(value.Attachment)},
	}
}

func fromWebAuthnCredential(value *webauthnlib.Credential) PasskeyCredential {
	transports := make([]string, len(value.Transport))
	for i := range value.Transport {
		transports[i] = string(value.Transport[i])
	}
	return PasskeyCredential{
		ID: value.ID, PublicKey: value.PublicKey, AttestationType: value.AttestationType, Transports: transports,
		UserPresent: value.Flags.UserPresent, UserVerified: value.Flags.UserVerified, BackupEligible: value.Flags.BackupEligible, BackupState: value.Flags.BackupState,
		AAGUID: value.Authenticator.AAGUID, SignCount: value.Authenticator.SignCount, CloneWarning: value.Authenticator.CloneWarning, Attachment: string(value.Authenticator.Attachment),
	}
}
