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
	"fmt"
	"net/mail"
	"strings"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/auth/u2f"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/trace"
	"github.com/sethvargo/go-diceware/diceware"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// AccountRecoveryEmailMarker is a marker in error messages to send emails to users.
// Also serves to send email one time.
const AccountRecoveryEmailMarker = "an email will be sent notifying user"

// fakeRecoveryCodeHash is bcrypt hash for "fake-barbaz x 8"
var fakeRecoveryCodeHash = []byte(`$2a$10$c2.h4pF9AA25lbrWo6U0D.ZmnYpFDaNzN3weNNYNC3jAkYEX9kpzu`)

// VerifyRecoveryCode verifies a given account recovery code.
// If an existing user fails to provide a correct code some number of times, user's account is temporarily locked
// from further recovery attempts and from logging in.
//
// Returns a reset token, subkind set to recovery.
func (s *Server) VerifyRecoveryCode(ctx context.Context, req *proto.VerifyRecoveryCodeRequest) (types.ResetPasswordToken, error) {
	if err := s.isAccountRecoveryAllowed(ctx); err != nil {
		return nil, trace.Wrap(err)
	}

	if req.GetUsername() == "" || req.GetRecoveryCode() == nil {
		return nil, trace.BadParameter("missing username or recovery code")
	}

	if _, err := mail.ParseAddress(req.GetUsername()); err != nil {
		return nil, trace.Wrap(err, "invalid email address: %q", req.GetUsername())
	}

	if err := s.withRecoveryAttemptCounter(ctx, req.GetRecoveryCode(), req.GetUsername()); err != nil {
		return nil, trace.Wrap(err)
	}

	// Remove any other existing reset tokens for this user before creating a token.
	if err := s.deleteResetPasswordTokens(ctx, req.Username); err != nil {
		return nil, trace.Wrap(err)
	}

	newTokenReq := CreateResetPasswordTokenRequest{
		Name: req.Username,
		Type: types.ResetPasswordTokenRecoveryStart,
	}

	subKind := types.KindRecoverPassword
	if req.IsResetSecondFactor {
		subKind = types.KindRecoverSecondFactor
	}

	token, err := s.createRecoveryToken(ctx, newTokenReq, subKind)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return s.GetResetPasswordToken(ctx, token.GetName())
}

func (s *Server) verifyRecoveryCode(ctx context.Context, user string, givenToken []byte) error {
	recovery, err := s.GetRecoveryCodes(ctx, user)
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}

	var hashedTokens []types.RecoveryCode
	userFound := true

	if trace.IsNotFound(err) {
		userFound = false
		log.Debugf("Account recovery tokens for user %q not found, using fake hashes to mitigate timing attacks.", user)
		hashedTokens = []types.RecoveryCode{{Value: fakeRecoveryCodeHash}, {Value: fakeRecoveryCodeHash}, {Value: fakeRecoveryCodeHash}}
	} else {
		hashedTokens = recovery.Codes
	}

	tokenMatch := false
	for i, token := range hashedTokens {
		if err = bcrypt.CompareHashAndPassword(token.Value, givenToken); err == nil {
			if !token.IsUsed && userFound {
				tokenMatch = true
				// Mark matched token as used in backend so it can't be used again.
				recovery.Codes[i].IsUsed = true
				if err := s.UpsertRecoveryCodes(ctx, user, *recovery); err != nil {
					return trace.Wrap(err)
				}
				break
			}
		}
	}

	event := &apievents.RecoveryCodeUsed{
		Metadata: apievents.Metadata{
			Type: events.RecoveryCodeUsedEvent,
			Code: events.RecoveryCodeUsedCode,
		},
		UserMetadata: apievents.UserMetadata{
			User: user,
		},
		Status: apievents.Status{
			Success: true,
		},
	}

	if !tokenMatch || !userFound {
		event.Status.Success = false
		event.Metadata.Code = events.RecoveryCodeUsedFailureCode
		traceErr := trace.NotFound("user not found")

		if !tokenMatch && userFound {
			traceErr = trace.BadParameter("account recovery token did not match")
		}

		event.Status.Error = traceErr.Error()
		event.Status.UserMessage = traceErr.Error()

		if err := s.emitter.EmitAuditEvent(s.closeCtx, event); err != nil {
			log.WithFields(logrus.Fields{"user": user}).Warn("Failed to emit account recovery token used failed event.")
		}

		return traceErr
	}

	if err := s.emitter.EmitAuditEvent(s.closeCtx, event); err != nil {
		log.WithFields(logrus.Fields{"user": user}).Warn("Failed to emit account recovery token used event.")
	}

	return nil
}

// withRecoveryAttemptCounter counts number of failed attempts at providing a valid recovery code.
// After max failed attempt, user is temporarily locked from further attempts at recovering and locked from
// logging in. This functions similar to WithUserLock.
func (a *Server) withRecoveryAttemptCounter(ctx context.Context, recoveryToken []byte, username string) error {
	user, err := a.GetUser(username, false)
	if err != nil {
		if trace.IsNotFound(err) {
			// If user is not found, still verify with fake tokens.
			// It should always return an error. This prevents timing attacks.
			return a.verifyRecoveryCode(ctx, username, recoveryToken)
		}
		return trace.Wrap(err)
	}

	status := user.GetStatus()
	if status.IsLocked && status.RecoveryAttemptLockExpires.After(a.clock.Now().UTC()) {
		return trace.AccessDenied("%v exceeds %v failed account recovery attempts, account locked until %v",
			user.GetName(), types.MaxRecoveryAttempts, apiutils.HumanTimeFormat(status.LockExpires))
	}

	fnErr := a.verifyRecoveryCode(ctx, username, recoveryToken)
	if fnErr == nil {
		err = a.DeleteRecoveryAttempt(ctx, username)
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}

		return nil
	}

	// Do not lock user in case if DB is flaky or down.
	if trace.IsConnectionProblem(fnErr) {
		return trace.Wrap(fnErr)
	}

	// Count failed attempt and possibly lock user.
	var attempt *types.RecoveryAttempt
	attempt, err = a.GetRecoveryAttempt(ctx, username)
	if err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		attempt = &types.RecoveryAttempt{Created: a.GetClock().Now().UTC()}
	}

	attempt.Increment()
	if attempt.Get() >= types.MaxRecoveryAttempts {
		lockUntil := a.clock.Now().UTC().Add(defaults.AccountLockInterval)
		message := fmt.Sprintf("%v exceeds %v failed account recovery attempts, account locked until %v and %v",
			username, types.MaxRecoveryAttempts, apiutils.HumanTimeFormat(status.LockExpires), AccountRecoveryEmailMarker)

		log.WithError(fnErr).Debug(message)

		// Lock both recovery attempt and login attempts.
		user.SetLocked(lockUntil, "user has exceeded maximum failed account recovery attempts")
		user.SetLockedFromRecoveryAttempt(lockUntil)

		if err := a.Identity.UpsertUser(user); err != nil {
			log.Error(trace.DebugReport(err))
			return trace.Wrap(fnErr)
		}

		return trace.AccessDenied(message)
	}

	log.Debugf("%v user has less than %v failed account recovery attempts", username, types.MaxRecoveryAttempts)

	if err := a.UpsertRecoveryAttempt(ctx, username, attempt); err != nil {
		log.Error(trace.DebugReport(err))
	}

	return trace.Wrap(fnErr)
}

// AuthenticateUserWithRecoveryToken authenticates user defined in token with either password or second factor.
// When a user provides a valid auth cred, the recovery token will be deleted, and a verified token will be created
// for use in next step in recovery flow.
//
// If a user fails to provide correct auth cred some number of times, the recovery token will be deleted and the user
// will have to start the recovery flow again with another recovery code. The user's account will also be locked from logging in.
func (s *Server) AuthenticateUserWithRecoveryToken(ctx context.Context, req *proto.AuthenticateUserWithRecoveryTokenRequest) (types.ResetPasswordToken, error) {
	if err := s.isAccountRecoveryAllowed(ctx); err != nil {
		return nil, trace.Wrap(err)
	}

	if req.TokenID == "" || req.Username == "" {
		return nil, trace.BadParameter("missing tokenId or username")
	}

	if req.GetPassword() == nil && req.GetSecondFactorToken() == "" && req.GetU2FSignResponse() == nil {
		return nil, trace.BadParameter("at least one authentication method is required")
	}

	token, err := s.GetResetPasswordToken(ctx, req.GetTokenID())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := token.CheckSubKindType(types.ResetPasswordTokenRecoveryStart); err != nil {
		return nil, trace.Wrap(err)
	}

	// This is to verify the username for emailing when user gets locked.
	if token.GetUser() != req.Username {
		return nil, trace.BadParameter("invalid username")
	}

	if token.Expiry().Before(s.clock.Now().UTC()) {
		return nil, trace.BadParameter("expired token")
	}

	// Begin authenticating user password or second factor.
	switch {
	case req.GetSecondFactorToken() != "":
		if token.GetSubKind() == types.KindRecoverSecondFactor {
			return nil, trace.BadParameter("user %q requested to recover second factor, expected password auth", token.GetUser())
		}
		return s.withResetTokenAuthAttemptCounter(ctx, token, func() error {
			_, err := s.checkOTP(token.GetUser(), req.GetSecondFactorToken())
			return err
		})

	case req.U2FSignResponse != nil:
		if token.GetSubKind() == types.KindRecoverSecondFactor {
			return nil, trace.BadParameter("user %q requested to recover second factor, expected password auth", token.GetUser())
		}
		return s.withResetTokenAuthAttemptCounter(ctx, token, func() error {
			_, err := s.CheckU2FSignResponse(ctx, token.GetUser(), &u2f.AuthenticateChallengeResponse{
				KeyHandle:     req.U2FSignResponse.GetKeyHandle(),
				SignatureData: req.U2FSignResponse.GetSignature(),
				ClientData:    req.U2FSignResponse.GetClientData(),
			})

			return err
		})

	default: // password
		if token.GetSubKind() == types.KindRecoverPassword {
			return nil, trace.BadParameter("user %q requested to recover password, expected second factor auth", token.GetUser())
		}

		return s.withResetTokenAuthAttemptCounter(ctx, token, func() error {
			return s.checkPasswordWOToken(token.GetUser(), req.Password)
		})
	}
}

// withResetTokenAuthAttemptCounter counts number of failed attempts at providing a valid password or second factor.
// After max failed attempts, user's account is temporarily locked from logging in, and the reset token is deleted.
func (a *Server) withResetTokenAuthAttemptCounter(ctx context.Context, token types.ResetPasswordToken, authenticateFn func() error) (types.ResetPasswordToken, error) {
	var fnErr error
	if token.GetAuthAttempts() < types.MaxRecoveryAttempts {
		fnErr = authenticateFn()
		if fnErr == nil {
			// Create an approved recovery token for next step in recovery flow.
			subKind := types.KindRecoverPasswordApproved
			if token.GetSubKind() == types.KindRecoverSecondFactor {
				subKind = types.KindRecoverSecondFactorApproved
			}

			approvedTokenReq := CreateResetPasswordTokenRequest{
				Name: token.GetUser(),
				Type: types.ResetPasswordTokenRecoveryApproved,
			}

			return a.createRecoveryToken(ctx, approvedTokenReq, subKind)
		}

		token.IncrementAuthAttempt()
	}

	// Do not update attempt counter in case if DB is flaky or down.
	if trace.IsConnectionProblem(fnErr) {
		return nil, trace.Wrap(fnErr)
	}

	// User is at last attempt, delete token and lock user's account.
	if token.GetAuthAttempts() == types.MaxRecoveryAttempts {
		lockUntil := a.clock.Now().UTC().Add(defaults.AccountLockInterval)
		message := fmt.Sprintf("%v exceeds %v failed reset token auth attempts, account locked until %v, deleted token %v, and %v",
			token.GetUser(), types.MaxRecoveryAttempts, apiutils.HumanTimeFormat(lockUntil), token.GetName(), AccountRecoveryEmailMarker)

		log.Debug(message)

		// Delete all token data related to this user.
		if err := a.deleteResetPasswordTokens(ctx, token.GetUser()); err != nil {
			log.Error(trace.DebugReport(err))
		}

		// Lock user account.
		user, err := a.GetUser(token.GetUser(), false)
		if err != nil {
			log.Error(trace.DebugReport(err))
			return nil, trace.Wrap(fnErr)
		}

		user.SetLocked(lockUntil, "user has exceeded maximum failed reset token auth attempts")
		if err := a.Identity.UpsertUser(user); err != nil {
			log.Error(trace.DebugReport(err))
			return nil, trace.Wrap(fnErr)
		}

		return nil, trace.AccessDenied(message)
	}

	log.Debugf("%v user has less than %v failed reset token auth attempts", token.GetUser(), types.MaxRecoveryAttempts)

	if err := a.UpdateResetPasswordToken(ctx, token); err != nil {
		log.Error(trace.DebugReport(err))
	}

	return nil, trace.Wrap(fnErr)
}

// ChangePasswordOrSecondFactor changes a user's password or resets their second factors with the new one provided.
// The reset token provided must be marked authenticated in order to change auth cred. When successful,
// lock is removed from user (if any) so they can login immediately.
//
// Returns new account recovery tokens.
func (s *Server) ChangePasswordOrSecondFactor(ctx context.Context, req *proto.ChangeUserAuthCredWithTokenRequest) (*proto.ChangePasswordOrSecondFactorResponse, error) {
	if err := s.isAccountRecoveryAllowed(ctx); err != nil {
		return nil, trace.Wrap(err)
	}

	if req.GetTokenID() == "" {
		return nil, trace.BadParameter("missing token")
	}

	if req.GetPassword() == nil && req.GetSecondFactorToken() == "" && req.GetU2FRegisterResponse() == nil {
		return nil, trace.BadParameter("missing new authentication cred")
	}

	token, err := s.GetResetPasswordToken(ctx, req.GetTokenID())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if token.Expiry().Before(s.clock.Now().UTC()) {
		return nil, trace.BadParameter("expired token")
	}

	if err := token.CheckSubKindType(types.ResetPasswordTokenRecoveryApproved); err != nil {
		return nil, trace.Wrap(err)
	}

	// Set new auth cred.
	if req.GetPassword() != nil {
		if token.GetSubKind() == types.KindRecoverSecondFactorApproved {
			return nil, trace.BadParameter("user %q requested to recover secondfactor, but received new password instead", token.GetUser())
		}

		// Set a new password.
		if err := s.UpsertPassword(token.GetUser(), req.Password); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if token.GetSubKind() == types.KindRecoverPasswordApproved {
			return nil, trace.BadParameter("user %q requested to recover password, but received new secondfactor instead", token.GetUser())
		}

		// Delete all previous mfa devices.
		if err := s.resetMFA(ctx, token.GetUser()); err != nil {
			return nil, trace.Wrap(err)
		}

		// Set the new second factor.
		if err := s.changeUserSecondFactor(req, token); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	// Delete all reset tokens.
	if err = s.deleteResetPasswordTokens(ctx, token.GetUser()); err != nil {
		return nil, trace.Wrap(err)
	}

	recoveryCodes, err := s.generateAndUpsertRecoveryCodes(ctx, token.GetUser())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Check and remove user login lock so user can immediately sign in after recovering.
	user, err := s.GetUser(token.GetUser(), false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if user.GetStatus().IsLocked {
		user.ResetLocks()
		if err := s.Identity.UpsertUser(user); err != nil {
			return nil, trace.Wrap(err)
		}

		if err := s.DeleteUserLoginAttempts(token.GetUser()); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return &proto.ChangePasswordOrSecondFactorResponse{
		Username:      token.GetUser(),
		RecoveryCodes: recoveryCodes,
	}, nil
}

func (s *Server) generateAndUpsertRecoveryCodes(ctx context.Context, username string) ([]string, error) {
	tokens, err := generateRecoveryCodes()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	hashedTokens := make([]types.RecoveryCode, len(tokens))
	for i, token := range tokens {
		hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		hashedTokens[i].Value = hashedToken
	}

	rc := types.NewRecoveryCodes(hashedTokens)
	rc.Created = s.GetClock().Now().UTC()

	if err := s.UpsertRecoveryCodes(ctx, username, *rc); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.emitter.EmitAuditEvent(s.closeCtx, &apievents.RecoveryCodeGenerate{
		Metadata: apievents.Metadata{
			Type: events.RecoveryCodeGeneratedEvent,
			Code: events.RecoveryCodesGeneratedCode,
		},
		UserMetadata: apievents.UserMetadata{
			User: username,
		},
	}); err != nil {
		log.WithError(err).WithFields(logrus.Fields{"user": username}).Warn("Failed to emit recovery tokens generate event.")
	}

	return tokens, nil
}

// isAccountRecoveryAllowed gets cluster auth configuration and check if local auth
// and second factor is allowed, which are required for account recovery.
func (s *Server) isAccountRecoveryAllowed(ctx context.Context) error {
	if modules.GetModules().Features().Cloud == false {
		return trace.AccessDenied("account recovery is only available for enterprise cloud")
	}

	authPref, err := s.GetAuthPreference(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	if !authPref.GetAllowLocalAuth() {
		return trace.AccessDenied("local auth needs to be enabled")
	}

	// Second factor must be otp, u2f, or on.
	if authPref.GetSecondFactor() == constants.SecondFactorOff || authPref.GetSecondFactor() == constants.SecondFactorOptional {
		return trace.AccessDenied("second factor must be enabled")
	}

	return nil
}

// generateRecoveryCodes returns an array of tokens where each token
// have 8 random words prefixed with tele and concanatenated with dashes.
func generateRecoveryCodes() ([]string, error) {
	gen, err := diceware.NewGenerator(nil)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tokenList := make([]string, types.NumOfRecoveryCodes)
	for i := 0; i < types.NumOfRecoveryCodes; i++ {
		list, err := gen.Generate(types.NumWordsInRecoveryCode)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		tokenList[i] = "tele-" + strings.Join(list, "-")
	}

	return tokenList, nil
}

// createRecoveryToken creates a reset token, where its subkind is set to recovery related kinds as a marker
// to differentiate between normal and recovery related tokens.
func (a *Server) createRecoveryToken(ctx context.Context, req CreateResetPasswordTokenRequest, subKind string) (types.ResetPasswordToken, error) {
	if req.Type != types.ResetPasswordTokenRecoveryStart && req.Type != types.ResetPasswordTokenRecoveryApproved {
		return nil, trace.BadParameter("invalid recovery token type")
	}

	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	newToken, err := a.newResetPasswordToken(req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Using subkind to mark token is for recovery and to remember
	// what kind of reset (password or secondfactor) the user requested.
	newToken.SetSubKind(subKind)

	if _, err := a.Identity.CreateResetPasswordToken(ctx, newToken); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := a.emitter.EmitAuditEvent(ctx, &apievents.ResetPasswordTokenCreate{
		Metadata: apievents.Metadata{
			Type: events.ResetPasswordTokenCreateEvent,
			Code: events.ResetPasswordTokenCreateCode,
		},
		UserMetadata: apievents.UserMetadata{
			User:         ClientUsername(ctx),
			Impersonator: ClientImpersonator(ctx),
		},
		ResourceMetadata: apievents.ResourceMetadata{
			Name:    req.Name,
			TTL:     req.TTL.String(),
			Expires: a.GetClock().Now().UTC().Add(req.TTL),
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit create reset password token event.")
	}

	return a.GetResetPasswordToken(ctx, newToken.GetName())
}
