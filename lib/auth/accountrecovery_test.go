/**
 * Copyright 2021 Gravitational, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/mocku2f"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/trace"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"github.com/tstranex/u2f"
)

type testWithCloudModules struct {
	modules.Modules
}

func (m *testWithCloudModules) Features() modules.Features {
	return modules.Features{
		Cloud: true, // Enable cloud feature which is required for account recovery.
	}
}

// TestGenerateUpsertAndVerifyRecoveryCodes tests the following:
//  - generation of recovery codes are of correct format
//  - recovery codes are upserted
//  - recovery codes can be verified and marked used
//  - reusing a used or non-existing token returns error
func TestGenerateUpsertAndVerifyRecoveryCodes(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()

	user := "fake@fake.com"
	rc, err := srv.Auth().generateAndUpsertRecoveryCodes(ctx, user)
	require.NoError(t, err)
	require.Len(t, rc, 3)

	// Test each codes are of correct format and used.
	for _, token := range rc {
		s := strings.Split(token, "-")

		// 9 b/c 1 for prefix, 8 for words.
		require.Len(t, s, 9)
		require.Contains(t, token, "tele-")

		// Test codes match.
		err := srv.Auth().verifyRecoveryCode(ctx, user, []byte(token))
		require.NoError(t, err)
	}

	// Test used codes are marked used.
	recovery, err := srv.Auth().GetRecoveryCodes(ctx, user)
	require.NoError(t, err)
	for _, token := range recovery.GetCodes() {
		require.True(t, token.IsUsed)
	}

	// Test with a used code returns error.
	err = srv.Auth().verifyRecoveryCode(ctx, user, []byte(rc[0]))
	require.True(t, trace.IsBadParameter(err))

	// Test with non-existing user returns error.
	err = srv.Auth().verifyRecoveryCode(ctx, "doesnotexist", []byte(rc[0]))
	require.True(t, trace.IsNotFound(err))
}

func TestRecoveryCodeEventsEmitted(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()
	mockEmitter := &events.MockEmitter{}
	srv.Auth().emitter = mockEmitter

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	user := "fake@fake.com"
	tc, err := srv.Auth().generateAndUpsertRecoveryCodes(ctx, user)
	require.NoError(t, err)
	event := mockEmitter.LastEvent()
	require.Equal(t, events.RecoveryCodeGeneratedEvent, event.GetType())
	require.Equal(t, events.RecoveryCodesGeneratedCode, event.GetCode())

	err = srv.Auth().verifyRecoveryCode(ctx, user, []byte(tc[0]))
	require.NoError(t, err)
	event = mockEmitter.LastEvent()
	require.Equal(t, events.RecoveryCodeUsedEvent, event.GetType())
	require.Equal(t, events.RecoveryCodeUsedCode, event.GetCode())

	// Re-using the same token should fail.
	err = srv.Auth().verifyRecoveryCode(ctx, user, []byte(tc[0]))
	require.Error(t, err)
	event = mockEmitter.LastEvent()
	require.Equal(t, events.RecoveryCodeUsedEvent, event.GetType())
	require.Equal(t, events.RecoveryCodeUsedFailureCode, event.GetCode())
}

// TestResetTOTPWithRecoveryTokenAndPassword tests a scenario where
// user has an accout with a password and u2f but lost their u2f key and user
// goes through the flow to reset second factor to a TOTP.
func TestResetTOTPWithRecoveryTokenAndPassword(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	// User starts with an account with a password and u2f.
	u, err := createUserAuthCreds(srv, "u2f")
	require.NoError(t, err)

	startToken, err := srv.Auth().VerifyRecoveryCode(ctx, &proto.VerifyRecoveryCodeRequest{
		Username:            u.username,
		RecoveryCode:        []byte(u.recoveryCodes[0]),
		IsResetSecondFactor: true,
	})
	require.NoError(t, err)
	require.Equal(t, startToken.GetSubKind(), types.KindRecoverSecondFactor)
	require.Equal(t, startToken.GetAuthAttempts(), int32(0))

	approvedToken, err := srv.Auth().AuthenticateUserWithRecoveryToken(ctx, &proto.AuthenticateUserWithRecoveryTokenRequest{
		TokenID:  startToken.GetName(),
		Username: startToken.GetUser(),
		Password: u.password,
	})
	require.NoError(t, err)
	require.Equal(t, approvedToken.GetSubKind(), types.KindRecoverSecondFactorApproved)

	// Change second factor to totp.
	newOTP, err := getOTPCode(srv, approvedToken.GetName())
	require.NoError(t, err)

	res2, err := srv.Auth().ChangePasswordOrSecondFactor(ctx, &proto.ChangeUserAuthCredWithTokenRequest{
		TokenID:           approvedToken.GetName(),
		SecondFactorToken: newOTP,
	})
	require.NoError(t, err)
	require.Equal(t, res2.Username, u.username)
	require.Len(t, res2.RecoveryCodes, 3)

	// Test only totp device is present.
	mfas, err := srv.Auth().GetMFADevices(ctx, u.username)
	require.NoError(t, err)
	require.Len(t, mfas, 1)
	require.NotEmpty(t, mfas[0].GetTotp())

	// Test new tokens work.
	for _, token := range res2.RecoveryCodes {
		_, err = srv.Auth().VerifyRecoveryCode(ctx, &proto.VerifyRecoveryCodeRequest{
			Username:     u.username,
			RecoveryCode: []byte(token),
		})
		require.NoError(t, err)
	}
}

// TestResetU2FWithRecoveryTokenAndPassword tests a scenario where
// user has an accout with a password and totp but somehow lost access to a totp authenticator
// and user goes through the flow to reset second factor to a u2f key.
func TestResetU2FWithRecoveryTokenAndPassword(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	// User starts with an account with a password and totp.
	u, err := createUserAuthCreds(srv, "otp")
	require.NoError(t, err)

	startToken, err := srv.Auth().VerifyRecoveryCode(ctx, &proto.VerifyRecoveryCodeRequest{
		Username:            u.username,
		RecoveryCode:        []byte(u.recoveryCodes[0]),
		IsResetSecondFactor: true,
	})
	require.NoError(t, err)

	approvedToken, err := srv.Auth().AuthenticateUserWithRecoveryToken(ctx, &proto.AuthenticateUserWithRecoveryTokenRequest{
		TokenID:  startToken.GetName(),
		Username: startToken.GetUser(),
		Password: []byte("abc123"),
	})
	require.NoError(t, err)

	// Change second factor to u2f.
	u2fRegResp, _, err := getMockedU2FAndRegisterRes(srv, approvedToken.GetName())
	require.NoError(t, err)

	res, err := srv.Auth().ChangePasswordOrSecondFactor(ctx, &proto.ChangeUserAuthCredWithTokenRequest{
		TokenID:             approvedToken.GetName(),
		U2FRegisterResponse: u2fRegResp,
	})
	require.NoError(t, err)
	require.Len(t, res.RecoveryCodes, 3)

	// Test only u2f device is present.
	mfas, err := srv.Auth().GetMFADevices(ctx, u.username)
	require.NoError(t, err)
	require.Len(t, mfas, 1)
	require.NotEmpty(t, mfas[0].GetU2F())
}

// TestChangePasswordWithRecoveryTokenAndOTP tests a scenario where
// user has an accout with a password and totp but lost their password and user
// goes through the flow to reset password.
func TestChangePasswordWithRecoveryTokenAndOTP(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	u, err := createUserAuthCreds(srv, "otp")
	require.NoError(t, err)

	startToken, err := srv.Auth().VerifyRecoveryCode(ctx, &proto.VerifyRecoveryCodeRequest{
		Username:            u.username,
		RecoveryCode:        []byte(u.recoveryCodes[0]),
		IsResetSecondFactor: false,
	})
	require.NoError(t, err)
	require.Equal(t, types.KindRecoverPassword, startToken.GetSubKind())

	// Get new otp code
	mfas, err := srv.Auth().GetMFADevices(ctx, u.username)
	require.NoError(t, err)

	newOTP, err := totp.GenerateCode(mfas[0].GetTotp().Key, srv.Clock().Now().Add(30*time.Second))
	require.NoError(t, err)

	approvedToken, err := srv.Auth().AuthenticateUserWithRecoveryToken(ctx, &proto.AuthenticateUserWithRecoveryTokenRequest{
		TokenID:           startToken.GetName(),
		Username:          startToken.GetUser(),
		SecondFactorToken: newOTP,
	})
	require.NoError(t, err)
	require.Equal(t, types.KindRecoverPasswordApproved, approvedToken.GetSubKind())

	// Change password
	newPassword := []byte("some-new-password")
	res2, err := srv.Auth().ChangePasswordOrSecondFactor(ctx, &proto.ChangeUserAuthCredWithTokenRequest{
		TokenID:  approvedToken.GetName(),
		Password: newPassword,
	})
	require.NoError(t, err)
	require.Len(t, res2.RecoveryCodes, 3)

	// Test old password doesn't work.
	err = srv.Auth().checkPasswordWOToken(u.username, u.password)
	require.Error(t, err)

	// Test new password.
	err = srv.Auth().checkPasswordWOToken(u.username, newPassword)
	require.NoError(t, err)
}

// TestChangePasswordWithRecoveryTokenAndU2F tests a scenario where
// user has an accout with a password and u2f key but lost their password and user
// goes through the flow to reset password.
func TestChangePasswordWithRecoveryTokenAndU2F(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	u, err := createUserAuthCreds(srv, "u2f")
	require.NoError(t, err)

	startToken, err := srv.Auth().VerifyRecoveryCode(ctx, &proto.VerifyRecoveryCodeRequest{
		Username:            u.username,
		RecoveryCode:        []byte(u.recoveryCodes[0]),
		IsResetSecondFactor: false,
	})
	require.NoError(t, err)

	// Get u2f challenge and sign.
	chal, err := srv.Auth().GetMFAAuthenticateChallengeWithToken(ctx, &proto.GetMFAAuthenticateChallengeWithTokenRequest{
		TokenID: startToken.GetName(),
	})
	require.NoError(t, err)

	u2f, err := u.u2fKey.SignResponse(&u2f.SignRequest{
		Version:   chal.GetU2F()[0].Version,
		Challenge: chal.GetU2F()[0].Challenge,
		KeyHandle: chal.GetU2F()[0].KeyHandle,
		AppID:     chal.GetU2F()[0].AppID,
	})
	require.NoError(t, err)

	approvedToken, err := srv.Auth().AuthenticateUserWithRecoveryToken(ctx, &proto.AuthenticateUserWithRecoveryTokenRequest{
		TokenID:  startToken.GetName(),
		Username: startToken.GetUser(),
		U2FSignResponse: &proto.U2FResponse{
			KeyHandle:  u2f.KeyHandle,
			ClientData: u2f.ClientData,
			Signature:  u2f.SignatureData,
		},
	})
	require.NoError(t, err)

	// Change password
	newPassword := []byte("some-new-password")
	res2, err := srv.Auth().ChangePasswordOrSecondFactor(ctx, &proto.ChangeUserAuthCredWithTokenRequest{
		TokenID:  approvedToken.GetName(),
		Password: newPassword,
	})
	require.NoError(t, err)
	require.Len(t, res2.RecoveryCodes, 3)

	// Test old password doesn't work.
	err = srv.Auth().checkPasswordWOToken(u.username, u.password)
	require.Error(t, err)

	// Test new password.
	err = srv.Auth().checkPasswordWOToken(u.username, newPassword)
	require.NoError(t, err)
}

func TestAccountRecoveryLock(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	u, err := createUserAuthCreds(srv, "otp")
	require.NoError(t, err)

	// Test invalid recovery codes locks user from further attempts at validating a recovery code.
	for i := 1; i <= types.MaxRecoveryAttempts; i++ {
		_, err = srv.Auth().VerifyRecoveryCode(ctx, &proto.VerifyRecoveryCodeRequest{
			Username:     u.username,
			RecoveryCode: []byte("invalid-code"),
		})
		require.Error(t, err)

		if i == types.MaxRecoveryAttempts {
			require.True(t, trace.IsAccessDenied(err))
			require.Contains(t, err.Error(), AccountRecoveryEmailMarker)
		}
	}

	// Make sure its locked.
	_, err = srv.Auth().VerifyRecoveryCode(ctx, &proto.VerifyRecoveryCodeRequest{
		Username:     u.username,
		RecoveryCode: []byte("invalid-code"),
	})
	require.True(t, trace.IsAccessDenied(err))

	// Test login and recovery attempt is actually locked.
	user, err := srv.Auth().GetUser(u.username, false)
	require.NoError(t, err)
	require.True(t, user.GetStatus().IsLocked)
	require.False(t, user.GetStatus().LockExpires.IsZero())
	require.False(t, user.GetStatus().RecoveryAttemptLockExpires.IsZero())
}

// TestRecoveryAllowedWithLoginLocked tests a user can still recover if they first
// locked themselves from max failed login attempts. After user successfully changes
// their auth cred, the locks are reset so user can login immediately after.
func TestRecoveryAllowedWithLoginLocked(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	u, err := createUserAuthCreds(srv, "otp")
	require.NoError(t, err)

	// Purposely get login locked.
	for i := 1; i <= defaults.MaxLoginAttempts; i++ {
		_, err = srv.Auth().authenticateUser(ctx, AuthenticateUserRequest{
			Username: u.username,
			OTP: &OTPCreds{
				Password: u.password,
				Token:    "invalid-token",
			},
		})
		require.Error(t, err)

		if i == defaults.MaxLoginAttempts {
			require.True(t, trace.IsAccessDenied(err))
		}
	}

	// Test login is locked but not recovery attempt.
	user, err := srv.Auth().GetUser(u.username, false)
	require.NoError(t, err)
	require.True(t, user.GetStatus().IsLocked)
	require.False(t, user.GetStatus().LockExpires.IsZero())
	require.True(t, user.GetStatus().RecoveryAttemptLockExpires.IsZero())

	// Still allow recovery.
	resetToken, err := srv.Auth().VerifyRecoveryCode(ctx, &proto.VerifyRecoveryCodeRequest{
		Username:            u.username,
		RecoveryCode:        []byte(u.recoveryCodes[0]),
		IsResetSecondFactor: false,
	})
	require.NoError(t, err)

	// Set up new totp.
	mfas, err := srv.Auth().GetMFADevices(ctx, u.username)
	require.NoError(t, err)

	newOTP, err := totp.GenerateCode(mfas[0].GetTotp().Key, srv.Clock().Now().Add(30*time.Second))
	require.NoError(t, err)

	resetToken, err = srv.Auth().AuthenticateUserWithRecoveryToken(ctx, &proto.AuthenticateUserWithRecoveryTokenRequest{
		TokenID:           resetToken.GetName(),
		Username:          resetToken.GetUser(),
		SecondFactorToken: newOTP,
	})
	require.NoError(t, err)

	// Change password to trigger unlock.
	newPassword := []byte("some-new-password")
	res2, err := srv.Auth().ChangePasswordOrSecondFactor(ctx, &proto.ChangeUserAuthCredWithTokenRequest{
		TokenID:  resetToken.GetName(),
		Password: newPassword,
	})
	require.NoError(t, err)
	require.Len(t, res2.RecoveryCodes, 3)

	// Test login locks are removed after successful changing of password.
	user, err = srv.Auth().GetUser(u.username, false)
	require.NoError(t, err)
	require.False(t, user.GetStatus().IsLocked)
	require.True(t, user.GetStatus().LockExpires.IsZero())
	require.True(t, user.GetStatus().RecoveryAttemptLockExpires.IsZero())
}

// TestResetTokenDeleteAfterMaxFailedAttempt tests if the reset token gets deleted and
// user is login locked if users reach max failed auth attempt with a reset token.
func TestResetTokenDeleteAfterMaxFailedAttempt(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	u, err := createUserAuthCreds(srv, "otp")
	require.NoError(t, err)

	resetToken, err := srv.Auth().VerifyRecoveryCode(ctx, &proto.VerifyRecoveryCodeRequest{
		Username:            u.username,
		RecoveryCode:        []byte(u.recoveryCodes[0]),
		IsResetSecondFactor: false,
	})
	require.NoError(t, err)

	// Test max failed attempt to trigger deleting of token and locking user.
	for i := 1; i <= types.MaxRecoveryAttempts; i++ {
		_, err = srv.Auth().AuthenticateUserWithRecoveryToken(ctx, &proto.AuthenticateUserWithRecoveryTokenRequest{
			TokenID:           resetToken.GetName(),
			Username:          resetToken.GetUser(),
			SecondFactorToken: "invalid-token",
		})
		require.Error(t, err)

		if i == types.MaxRecoveryAttempts {
			require.Contains(t, err.Error(), AccountRecoveryEmailMarker)
		}
	}

	// Test verifying reset token after lock, returns a not found error.
	_, err = srv.Auth().AuthenticateUserWithRecoveryToken(ctx, &proto.AuthenticateUserWithRecoveryTokenRequest{
		TokenID:           resetToken.GetName(),
		Username:          resetToken.GetUser(),
		SecondFactorToken: "invalid-token",
	})
	require.Error(t, err)
	require.True(t, trace.IsNotFound(err))

	// Test only login is actually locked.
	user, err := srv.Auth().GetUser(u.username, false)
	require.NoError(t, err)
	require.True(t, user.GetStatus().IsLocked)
	require.False(t, user.GetStatus().LockExpires.IsZero())
	require.True(t, user.GetStatus().RecoveryAttemptLockExpires.IsZero())
}

func TestRecoveryInvalidEmailAndTokenType(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	u, err := createUserAuthCreds(srv, "otp")
	require.NoError(t, err)

	// Test invalid email address as username.
	_, err = srv.Auth().VerifyRecoveryCode(ctx, &proto.VerifyRecoveryCodeRequest{
		Username:     "invalid-username",
		RecoveryCode: []byte(u.recoveryCodes[0]),
	})
	require.Error(t, err)

	wrongToken, err := srv.Auth().CreateResetPasswordToken(ctx, CreateResetPasswordTokenRequest{
		Name: u.username,
		Type: types.ResetPasswordTokenInvite,
	})

	// Test wrong token type for authenticating user.
	_, err = srv.Auth().AuthenticateUserWithRecoveryToken(ctx, &proto.AuthenticateUserWithRecoveryTokenRequest{
		TokenID:           wrongToken.GetName(),
		Username:          wrongToken.GetUser(),
		SecondFactorToken: "should-not-matter",
	})
	require.Contains(t, err.Error(), "invalid token subkind")

	// Test wrong token type for changing a user auth cred.
	_, err = srv.Auth().ChangePasswordOrSecondFactor(ctx, &proto.ChangeUserAuthCredWithTokenRequest{
		TokenID:           wrongToken.GetName(),
		SecondFactorToken: "should-not-matter",
	})
	require.Contains(t, err.Error(), "invalid token subkind")

	// Test recovery token with wrong subkind for authenticating user.
	wrongToken, err = srv.Auth().createRecoveryToken(ctx, CreateResetPasswordTokenRequest{
		Name: u.username,
		Type: types.ResetPasswordTokenRecoveryApproved,
	}, types.KindRecoverPasswordApproved)

	_, err = srv.Auth().AuthenticateUserWithRecoveryToken(ctx, &proto.AuthenticateUserWithRecoveryTokenRequest{
		TokenID:           wrongToken.GetName(),
		Username:          wrongToken.GetUser(),
		SecondFactorToken: "should-not-matter",
	})
	require.Contains(t, err.Error(), "invalid token subkind")

	// Test recovery token with wrong subkind for changing a user auth cred.
	wrongToken, err = srv.Auth().createRecoveryToken(ctx, CreateResetPasswordTokenRequest{
		Name: u.username,
		Type: types.ResetPasswordTokenRecoveryStart,
	}, types.KindRecoverPassword)
	_, err = srv.Auth().ChangePasswordOrSecondFactor(ctx, &proto.ChangeUserAuthCredWithTokenRequest{
		TokenID:           wrongToken.GetName(),
		SecondFactorToken: "should-not-matter",
	})
	require.Contains(t, err.Error(), "invalid token subkind")
}

type userAuthCreds struct {
	recoveryCodes []string
	username      string
	password      []byte
	u2fKey        *mocku2f.Key
}

func createUserAuthCreds(srv *TestTLSServer, secondFactor string) (*userAuthCreds, error) {
	ctx := context.Background()
	username := "fake@fake.com"
	password := []byte("abc123")

	ap, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type:         constants.Local,
		SecondFactor: constants.SecondFactorOn,
		U2F: &types.U2F{
			AppID:  "teleport",
			Facets: []string{"teleport"},
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := srv.Auth().SetAuthPreference(ctx, ap); err != nil {
		return nil, trace.Wrap(err)
	}

	_, _, err = CreateUserAndRole(srv.Auth(), username, []string{username})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resetToken, err := srv.Auth().CreateResetPasswordToken(context.TODO(), CreateResetPasswordTokenRequest{
		Name: username,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var res *types.ChangePasswordWithTokenResponse
	if secondFactor == "otp" {
		otp, err := getOTPCode(srv, resetToken.GetName())
		if err != nil {
			return nil, trace.Wrap(err)
		}

		res, err = srv.Auth().ChangePasswordWithToken(ctx, &proto.ChangeUserAuthCredWithTokenRequest{
			TokenID:           resetToken.GetName(),
			Password:          password,
			SecondFactorToken: otp,
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	var u2fKey *mocku2f.Key
	if secondFactor == "u2f" {
		var u2fRegResp *proto.U2FRegisterResponse
		u2fRegResp, u2fKey, err = getMockedU2FAndRegisterRes(srv, resetToken.GetName())
		res, err = srv.Auth().ChangePasswordWithToken(ctx, &proto.ChangeUserAuthCredWithTokenRequest{
			TokenID:             resetToken.GetName(),
			Password:            password,
			U2FRegisterResponse: u2fRegResp,
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return &userAuthCreds{
		recoveryCodes: res.RecoveryCodes,
		username:      username,
		password:      []byte("abc123"),
		u2fKey:        u2fKey,
	}, nil
}

func getOTPCode(srv *TestTLSServer, tokenID string) (string, error) {
	secrets, err := srv.Auth().RotateResetPasswordTokenSecrets(context.TODO(), tokenID)
	if err != nil {
		return "", trace.Wrap(err)
	}

	otp, err := totp.GenerateCode(secrets.GetOTPKey(), srv.Clock().Now())
	if err != nil {
		return "", trace.Wrap(err)
	}

	return otp, nil
}

func getMockedU2FAndRegisterRes(srv *TestTLSServer, tokenID string) (*proto.U2FRegisterResponse, *mocku2f.Key, error) {
	res, err := srv.Auth().CreateSignupU2FRegisterRequest(tokenID)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	u2fKey, err := mocku2f.Create()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	u2fRegResp, err := u2fKey.RegisterResponse(res)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	return &proto.U2FRegisterResponse{
		RegistrationData: u2fRegResp.RegistrationData,
		ClientData:       u2fRegResp.ClientData,
	}, u2fKey, nil
}
