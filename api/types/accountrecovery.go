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

package types

import (
	"time"

	"github.com/gravitational/trace"
)

const (
	NumOfRecoveryCodes     = 3
	NumWordsInRecoveryCode = 8

	RecoveryTokenLenBytes = 32
	MaxRecoveryTokenTTL   = 3 * time.Hour
	MaxRecoveryAttempts   = 3

	KindRecoveryCodes = "recovery_codes"

	KindRecoverPassword             = "recover_password"
	KindRecoverSecondFactor         = "recover_secondfactor"
	KindRecoverPasswordApproved     = "recover_password_approved"
	KindRecoverSecondFactorApproved = "recover_secondfactor_approved"
)

// NewRecoveryCodes creates a new RecoveryCodes with the given codes.
// Caller must set the Created field.
func NewRecoveryCodes(codes []RecoveryCode) *RecoveryCodes {
	return &RecoveryCodes{
		Kind:    KindRecoveryCodes,
		Version: V1,
		Codes:   codes,
	}
}

// CheckAndSetDefaults validates fields and populates empty fields with default values.
func (t *RecoveryCodes) CheckAndSetDefaults() error {
	if t.Kind == "" {
		return trace.BadParameter("missing Kind field")
	}

	if t.Version == "" {
		t.Version = V1
	}

	if t.Codes == nil || len(t.Codes) < NumOfRecoveryCodes {
		return trace.BadParameter("invalid Codes field")
	}

	if t.Created.IsZero() {
		return trace.BadParameter("missing Created field")
	}

	return nil
}

func (t *RecoveryCodes) GetKind() string               { return t.Kind }
func (t *RecoveryCodes) GetVersion() string            { return t.Version }
func (t *RecoveryCodes) GetCodes() []RecoveryCode      { return t.Codes }
func (t *RecoveryCodes) SetCreation(created time.Time) { t.Created = created }

// RecoveryAttempt is used to keep count of users failed attempts
// at providing a valid recovery code.
type RecoveryAttempt struct {
	// Attempts indicates number of times user failed.
	Attempts int32 `json:"attempts"`
	// Created is when this attempt was created.
	Created time.Time `json:"created"`
}

func (a *RecoveryAttempt) Increment()            { a.Attempts += 1 }
func (a *RecoveryAttempt) Get() int32            { return a.Attempts }
func (a *RecoveryAttempt) GetCreated() time.Time { return a.Created }
func (a *RecoveryAttempt) Check() error {
	if a.Created.IsZero() {
		return trace.BadParameter("missing parameter Created")
	}

	return nil
}

// ChangePasswordWithTokenResponse defines the response to a successful changing of password.
type ChangePasswordWithTokenResponse struct {
	WebSession    WebSession
	RecoveryCodes []string
}
