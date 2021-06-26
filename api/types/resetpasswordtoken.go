/*
Copyright 2020 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package types

import (
	"fmt"
	"time"

	"github.com/gravitational/trace"
)

const (
	// ResetPasswordTokenInvite indicates invite UI flow.
	ResetPasswordTokenInvite = "invite"
	// ResetPasswordTokenPassword indicates set new password UI flow.
	ResetPasswordTokenPassword = "password"
	// ResetPasswordTokenRecoveryStart indicates start recovery UI flow.
	ResetPasswordTokenRecoveryStart = "recovery_start"
	// ResetPasswordTokenRecoveryApproved indicates recover new password or second factor UI flow.
	ResetPasswordTokenRecoveryApproved = "recovery_approved"
)

// ResetPasswordToken represents a temporary token used to reset passwords
type ResetPasswordToken interface {
	// Resource provides common resource properties
	Resource
	// GetUser returns User
	GetUser() string
	// SetUser sets User
	SetUser(string)
	// GetCreated returns Created
	GetCreated() time.Time
	// SetCreated sets Created
	SetCreated(time.Time)
	// GetURL returns URL
	GetURL() string
	// SetURL returns URL
	SetURL(string)
	// IncrementAuthAttempt increases the attempt counter by 1.
	IncrementAuthAttempt()
	// GetAuthAttempts returns number of failed auth attempts.
	GetAuthAttempts() int32
	// CheckSubKindType checks if given token type matches with the subkind.
	CheckSubKindType(tokenType string) error
}

// NewResetPasswordToken creates an instance of ResetPasswordToken.
func NewResetPasswordToken(tokenID string) (ResetPasswordToken, error) {
	u := &ResetPasswordTokenV3{
		Metadata: Metadata{
			Name: tokenID,
		},
	}
	if err := u.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return u, nil
}

// GetName returns Name
func (u *ResetPasswordTokenV3) GetName() string {
	return u.Metadata.Name
}

// SetName sets the name of the resource
func (u *ResetPasswordTokenV3) SetName(name string) {
	u.Metadata.Name = name
}

// GetUser returns User
func (u *ResetPasswordTokenV3) GetUser() string {
	return u.Spec.User
}

// SetUser sets the name of the resource
func (u *ResetPasswordTokenV3) SetUser(name string) {
	u.Spec.User = name
}

// GetCreated returns Created
func (u *ResetPasswordTokenV3) GetCreated() time.Time {
	return u.Spec.Created
}

// SetCreated sets the name of the resource
func (u *ResetPasswordTokenV3) SetCreated(t time.Time) {
	u.Spec.Created = t
}

// GetURL returns URL
func (u *ResetPasswordTokenV3) GetURL() string {
	return u.Spec.URL
}

// SetURL sets URL
func (u *ResetPasswordTokenV3) SetURL(url string) {
	u.Spec.URL = url
}

// Expiry returns object expiry setting
func (u *ResetPasswordTokenV3) Expiry() time.Time {
	return u.Metadata.Expiry()
}

// SetExpiry sets object expiry
func (u *ResetPasswordTokenV3) SetExpiry(t time.Time) {
	u.Metadata.SetExpiry(t)
}

// GetMetadata returns object metadata
func (u *ResetPasswordTokenV3) GetMetadata() Metadata {
	return u.Metadata
}

// GetVersion returns resource version
func (u *ResetPasswordTokenV3) GetVersion() string {
	return u.Version
}

// GetKind returns resource kind
func (u *ResetPasswordTokenV3) GetKind() string {
	return u.Kind
}

// GetResourceID returns resource ID
func (u *ResetPasswordTokenV3) GetResourceID() int64 {
	return u.Metadata.ID
}

// SetResourceID sets resource ID
func (u *ResetPasswordTokenV3) SetResourceID(id int64) {
	u.Metadata.ID = id
}

// GetSubKind returns resource sub kind
func (u *ResetPasswordTokenV3) GetSubKind() string {
	return u.SubKind
}

// SetSubKind sets resource subkind
func (u *ResetPasswordTokenV3) SetSubKind(s string) {
	u.SubKind = s
}

// setStaticFields sets static resource header and metadata fields.
func (u *ResetPasswordTokenV3) setStaticFields() {
	u.Kind = KindResetPasswordToken
	u.Version = V3
}

// CheckAndSetDefaults checks and set default values for any missing fields.
func (u *ResetPasswordTokenV3) CheckAndSetDefaults() error {
	u.setStaticFields()
	if err := u.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// // String represents a human readable version of the token
func (u *ResetPasswordTokenV3) String() string {
	return fmt.Sprintf("ResetPasswordTokenV3(tokenID=%v, user=%v, expires at %v)", u.GetName(), u.Spec.User, u.Expiry())
}

// IncrementAuthAttempt increases the attempt counter by 1.
func (u *ResetPasswordTokenV3) IncrementAuthAttempt() {
	u.AuthAttempts += 1
}

// GetAuthAttempts returns number of failed auth attempts.
func (u *ResetPasswordTokenV3) GetAuthAttempts() int32 {
	return u.AuthAttempts
}

// CheckSubKindType checks if given token type matches with the subkind.
func (u *ResetPasswordTokenV3) CheckSubKindType(tokenType string) error {
	if tokenType == ResetPasswordTokenRecoveryStart {
		if u.GetSubKind() != KindRecoverPassword && u.GetSubKind() != KindRecoverSecondFactor {
			return trace.BadParameter("invalid token subkind")
		}
		return nil
	}

	if tokenType == ResetPasswordTokenRecoveryApproved {
		if u.GetSubKind() != KindRecoverPasswordApproved && u.GetSubKind() != KindRecoverSecondFactorApproved {
			return trace.BadParameter("invalid token subkind")
		}
		return nil
	}

	return trace.BadParameter("unknown reset password token type")
}
