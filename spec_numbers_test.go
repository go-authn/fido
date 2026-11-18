// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import "testing"

// TestNumbersAreTheSpecifications pins every command byte and map key the
// virtual authenticator shares with the package to the number CTAP 2.1
// (Proposed Standard, errata 2022-06-21) prints for it. The fake builds its
// replies from these same constants, so a wrong one would be echoed back as
// correct; this table is the independent side. The "want" column is copied
// from the specification's tables, not from the constants.
func TestNumbersAreTheSpecifications(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want int64
	}{
		// 6.1-6.13: command bytes.
		{"authenticatorMakeCredential (6.1)", int64(CmdMakeCredential), 0x01},
		{"authenticatorGetAssertion (6.2)", int64(CmdGetAssertion), 0x02},
		{"authenticatorGetNextAssertion (6.3)", int64(CmdGetNextAssertion), 0x08},
		{"authenticatorGetInfo (6.4)", int64(CmdGetInfo), 0x04},
		{"authenticatorClientPIN (6.5)", int64(CmdClientPIN), 0x06},
		{"authenticatorBioEnrollment (6.7)", int64(CmdBioEnrollment), 0x09},
		{"authenticatorCredentialManagement (6.8)", int64(CmdCredentialManagement), 0x0A},
		{"Prototype authenticatorBioEnrollment (6.12)", int64(CmdBioEnrollmentPreview), 0x40},
		{"Prototype authenticatorCredentialManagement (6.13)", int64(CmdCredentialManagementPreview), 0x41},

		// 6.4: getInfo response.
		{"getInfo versions", infoVersions, 0x01},
		{"getInfo extensions", infoExtensions, 0x02},
		{"getInfo aaguid", infoAAGUID, 0x03},
		{"getInfo options", infoOptions, 0x04},
		{"getInfo maxMsgSize", infoMaxMsgSize, 0x05},
		{"getInfo pinUvAuthProtocols", infoPINProtocols, 0x06},
		{"getInfo transports", infoTransports, 0x09},
		{"getInfo forcePINChange", infoForcePIN, 0x0C},
		{"getInfo minPINLength", infoMinPINLength, 0x0D},

		// 6.1: makeCredential.
		{"makeCredential clientDataHash", mcClientDataHash, 0x01},
		{"makeCredential rp", mcRP, 0x02},
		{"makeCredential user", mcUser, 0x03},
		{"makeCredential pubKeyCredParams", mcPubKeyCredParams, 0x04},
		{"makeCredential excludeList", mcExcludeList, 0x05},
		{"makeCredential extensions", mcExtensions, 0x06},
		{"makeCredential options", mcOptions, 0x07},
		{"makeCredential pinUvAuthParam", mcPinUvAuthParam, 0x08},
		{"makeCredential pinUvAuthProtocol", mcPinUvAuthProtocol, 0x09},
		{"makeCredential response fmt", mcRespFmt, 0x01},
		{"makeCredential response authData", mcRespAuthData, 0x02},
		{"makeCredential response attStmt", mcRespAttStmt, 0x03},

		// 6.2: getAssertion.
		{"getAssertion rpId", gaRPID, 0x01},
		{"getAssertion clientDataHash", gaClientDataHash, 0x02},
		{"getAssertion allowList", gaAllowList, 0x03},
		{"getAssertion extensions", gaExtensions, 0x04},
		{"getAssertion options", gaOptions, 0x05},
		{"getAssertion pinUvAuthParam", gaPinUvAuthParam, 0x06},
		{"getAssertion pinUvAuthProtocol", gaPinUvAuthProtocol, 0x07},
		{"getAssertion response credential", gaRespCredential, 0x01},
		{"getAssertion response authData", gaRespAuthData, 0x02},
		{"getAssertion response signature", gaRespSignature, 0x03},
		{"getAssertion response user", gaRespUser, 0x04},
		{"getAssertion response numberOfCredentials", gaRespAvailable, 0x05},

		// 6.5.5: clientPIN.
		{"clientPIN pinUvAuthProtocol", cpProtocol, 0x01},
		{"clientPIN subCommand", cpSubCommand, 0x02},
		{"clientPIN keyAgreement", cpKeyAgreement, 0x03},
		{"clientPIN pinUvAuthParam", cpPinUvAuthParam, 0x04},
		{"clientPIN newPinEnc", cpNewPinEnc, 0x05},
		{"clientPIN pinHashEnc", cpPinHashEnc, 0x06},
		{"clientPIN permissions", cpPermissions, 0x09},
		{"clientPIN rpId", cpRPID, 0x0A},
		{"clientPIN getPINRetries", subGetPINRetries, 0x01},
		{"clientPIN getKeyAgreement", subGetKeyAgreement, 0x02},
		{"clientPIN setPIN", subSetPIN, 0x03},
		{"clientPIN changePIN", subChangePIN, 0x04},
		{"clientPIN getPinToken", subGetPINToken, 0x05},
		{"clientPIN getPinUvAuthTokenUsingUvWithPermissions", subGetTokenUsingUV, 0x06},
		{"clientPIN getUVRetries", subGetUVRetries, 0x07},
		{"clientPIN getPinUvAuthTokenUsingPinWithPermissions", subGetTokenUsingPIN, 0x09},
		{"clientPIN response keyAgreement", cpRespKeyAgreement, 0x01},
		{"clientPIN response pinUvAuthToken", cpRespToken, 0x02},
		{"clientPIN response pinRetries", cpRespPINRetries, 0x03},
		{"clientPIN response powerCycleState", cpRespPowerCycle, 0x04},
		{"clientPIN response uvRetries", cpRespUVRetries, 0x05},
		{"permission mc", int64(PermMakeCredential), 0x01},
		{"permission ga", int64(PermGetAssertion), 0x02},
		{"permission cm", int64(PermCredentialManagement), 0x04},
		{"permission be", int64(PermBioEnrollment), 0x08},
		{"permission lbw", int64(PermLargeBlobWrite), 0x10},
		{"permission acfg", int64(PermAuthenticatorConfig), 0x20},

		// 6.8: credentialManagement.
		{"credMgmt subCommand", cmSub, 0x01},
		{"credMgmt subCommandParams", cmParams, 0x02},
		{"credMgmt pinUvAuthProtocol", cmProto, 0x03},
		{"credMgmt pinUvAuthParam", cmAuth, 0x04},
		{"credMgmt enumerateCredentialsBegin", cmEnumerateCredentialsBegin, 0x04},
		{"credMgmt enumerateCredentialsGetNextCredential", cmEnumerateCredentialsNext, 0x05},
		{"credMgmt deleteCredential", cmDeleteCredential, 0x06},
		{"credMgmt param rpIDHash", cmpRPIDHash, 0x01},
		{"credMgmt param credentialID", cmpCredentialID, 0x02},
		{"credMgmt response user", cmrUser, 0x06},
		{"credMgmt response credentialID", cmrCredentialID, 0x07},
		{"credMgmt response totalCredentials", cmrTotalCreds, 0x09},

		// 6.7: bioEnrollment.
		{"bio modality", bioModality, 0x01},
		{"bio subCommand", bioSub, 0x02},
		{"bio subCommandParams", bioParams, 0x03},
		{"bio pinUvAuthProtocol", bioProtocol, 0x04},
		{"bio pinUvAuthParam", bioAuthParam, 0x05},
		{"bio modality fingerprint", modalityFingerprint, 0x01},
		{"bio enrollBegin", subEnrollBegin, 0x01},
		{"bio enrollCaptureNextSample", subEnrollNext, 0x02},
		{"bio cancelCurrentEnrollment", subEnrollCancel, 0x03},
		{"bio enumerateEnrollments", subEnumerate, 0x04},
		{"bio setFriendlyName", subSetName, 0x05},
		{"bio removeEnrollment", subRemove, 0x06},
		{"bio getFingerprintSensorInfo", subSensorInfo, 0x07},
		{"bio param templateId", bpTemplateID, 0x01},
		{"bio param templateFriendlyName", bpName, 0x02},
		{"bio param timeoutMilliseconds", bpTimeout, 0x03},
		{"bio response fingerprintKind", brKind, 0x02},
		{"bio response maxCaptureSamplesRequiredForEnroll", brMaxSamples, 0x03},
		{"bio response templateId", brTemplateID, 0x04},
		{"bio response lastEnrollSampleStatus", brLastStatus, 0x05},
		{"bio response remainingSamples", brRemaining, 0x06},
		{"bio response templateInfos", brTemplateInfos, 0x07},
		{"bio response maxTemplateFriendlyName", brMaxName, 0x08},

		// 12.1: credProtect values.
		{"userVerificationOptional", int64(CredProtectOptional), 0x01},
		{"userVerificationOptionalWithCredentialIDList", int64(CredProtectOptionalWithList), 0x02},
		{"userVerificationRequired", int64(CredProtectRequired), 0x03},
	} {
		if c.got != c.want {
			t.Errorf("%s is %#02x in this package, %#02x in CTAP 2.1", c.name, c.got, c.want)
		}
	}
}
