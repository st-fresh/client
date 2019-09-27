// Copyright 2019 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package libkb

import (
	"fmt"
	"time"

	"github.com/keybase/client/go/protocol/keybase1"
)

func randomPassphraseToState(bool hasRandomPassphrase) keybase1.PassphraseState {
	if hasRandomPassphrase {
		return keybase1.PassphraseState_RANDOM
	}
	return keybase1.PassphraseState_KNOWN
}

func LoadPassphraseState(mctx MetaContext, arg keybase1.LoadPassphraseStateArg) (passphraseState keybase1.PassphraseState, err error) {
	mctx = mctx.WithLogTag("PPSTATE")
	defer mctx.TraceTimed(fmt.Sprintf("LoadPassphraseState(forceRepoll=%t)", arg.ForceRepoll), func() error { return err })()

	if !mctx.G().ActiveDevice.Valid() {
		mctx.Debug("LoadPassphraseState: user is not logged in")
		return passphraseState, NewLoginRequiredError("LoadPassphraseState")
	}

	configState := mctx.G().Env.GetConfigWriter().GetPassphraseState()
	if configState != nil {
		mctx.Debug("LoadPassphraseState: state found in config.json")
		return *configState
	}
	mctx.Debug("LoadPassphraseState: state not found in config.json; checking legacy leveldb")

	legacyState, err := loadPassphraseStateFromLegacy(mctx)
	if err == nil {
		MaybeSavePassphraseState(legacyState)
		return legacyState, nil
	}
	mctx.Debug("LoadPassphraseState: could not find state in legacy leveldb (%s); checking remote", err)

	remoteState, err := loadPassphraseStateFromRemote(mctx)
	if err == nil {
		MaybeSavePassphraseState(remoteState)
		return remoteState, nil
	}
	return passphraseState, fmt.Errorf("failed to load passphrase state from remote: %s", err)
}

func MaybeSavePassphraseState(mctx MetaContext, passphraseState keybase1.PassphraseState) {
	err := mctx.G().Env.GetConfigWriter().SetPassphraseState(passphraseState)
	if err == nil {
		mctx.Debug("Added PassphraseState=%#v to config file", passphraseState)
	} else {
		mctx.Warning("Failed to save passphraseState=%#v to config file: %s", passphraseState, err)
	}
}

func loadPassphraseStateFromLegacy(mctx MetaContext) (passphraseState keybase1.PassphraseState, err error) {
	currentUID := mctx.CurrentUID()
	cacheKey := DbKey{
		Typ: DBLegacyHasRandomPW,
		Key: currentUID.String(),
	}
	var hasRandomPassphrase bool
	found, err := mctx.G().GetKVStore().GetInto(&hasRandomPassphrase, cacheKey)
	if err != nil {
		return passphraseState, err
	}
	if !found {
		return passphraseState, fmt.Errorf("passphrase state not found in leveldb")
	}
	return randomPassphraseToState(hasRandomPassphrase), nil
}

func loadPassphraseStateFromRemote(mctx MetaContext) (passphraseState keybase1.PassphraseState, err error) {
	var ret struct {
		AppStatusEmbed
		RandomPassphrase bool `json:"random_pw"`
	}
	err = mctx.G().API.GetDecode(mctx, APIArg{
		Endpoint:       "user/has_random_pw",
		SessionType:    APISessionTypeREQUIRED,
		InitialTimeout: 10 * time.Second,
	}, &ret)
	if err != nil {
		return passphraseState, err
	}
	return randomPassphraseToState(ret.RandomPassphrase), nil
}

func CanLogout(mctx MetaContext) (res keybase1.CanLogoutRes) {
	if !mctx.G().ActiveDevice.Valid() {
		mctx.Debug("CanLogout: looks like user is not logged in")
		res.CanLogout = true
		return res
	}

	if mctx.G().ActiveDevice.KeychainMode() == KeychainModeNone {
		mctx.Debug("CanLogout: ok to logout since the key used doesn't user the keychain")
		res.CanLogout = true
		return res
	}

	if err := CheckCurrentUIDDeviceID(mctx); err != nil {
		switch err.(type) {
		case DeviceNotFoundError, UserNotFoundError,
			KeyRevokedError, NoDeviceError, NoUIDError:
			mctx.Debug("CanLogout: allowing logout because of CheckCurrentUIDDeviceID returning: %s", err.Error())
			return keybase1.CanLogoutRes{CanLogout: true}
		default:
			// Unexpected error like network connectivity issue, fall through.
			// Even if we are offline here, we may be able to get cached value
			// `false` from LoadHasRandomPw and be allowed to log out.
			mctx.Debug("CanLogout: CheckCurrentUIDDeviceID returned: %q, falling through", err.Error())
		}
	}

	hasRandomPW, err := LoadHasRandomPw(mctx, keybase1.LoadHasRandomPwArg{
		ForceRepoll: false,
	})

	if err != nil {
		return keybase1.CanLogoutRes{
			CanLogout: false,
			Reason:    fmt.Sprintf("We couldn't ensure that your account has a passphrase: %s", err.Error()),
		}
	}

	if hasRandomPW {
		return keybase1.CanLogoutRes{
			CanLogout:     false,
			SetPassphrase: true,
			Reason:        "You signed up without a password and need to set a password first",
		}
	}

	res.CanLogout = true
	return res
}
