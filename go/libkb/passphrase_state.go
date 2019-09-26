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

	state := mctx.G().Env.GetConfigWriter().GetPassphraseState()

	if state != nil {
		mctx.Debug("LoadPassphraseState: state found in config.json")
		return *state
	}

	mctx.Debug("LoadPassphraseState: state not found in config.json; checking legacy leveldb")

	currentUID := mctx.CurrentUID()
	cacheKey := DbKey{
		Typ: DBLegacyHasRandomPW,
		Key: currentUID.String(),
	}
	var hasRandomPassphrase bool
	found, err := mctx.G().GetKVStore().GetInto(&hasRandomPassphrase, cacheKey)
	if err == nil && found {
		newState := randomPassphraseToState(hasRandomPassphrase)

		err := mctx.G().Env.GetConfigWriter().SetPassphraseState(newState)
		if err == nil {
			mctx.Debug("Added PassphraseState=%#v to config file", newState)
		} else {
			mctx.Warning("Failed to save PassphraseState to config file: %s", err)
		}

		return newState, nil
	}

	mctx.Debug("LoadPassphraseState: passphrase state not found in leveldb, checking from remote (err=%s, found=%t)",
		err, found)

	newState := randomPassphraseToState(ret.RandomPassphrase)
	if state == nil {
		err := mctx.G().Env.GetConfigWriter().SetPassphraseState(newState)
		if err == nil {
			mctx.Debug("Added PassphraseState=%#v to config file", newState)
		} else {
			mctx.Warning("Failed to save PassphraseState to config file: %s", err)
		}
	}

	return newState, err
}

func LoadPassphraseStateFromRemote(mctx MetaContext, arg keybase1.LoadPassphraseStateArg) (passphraseState keybase1.PassphraseState, err error) {
	var initialTimeout time.Duration
	if !arg.NoShortTimeout {
		// If we are do not need accurate response from the API server, make
		// the request with a timeout for quicker overall RPC response time
		// if network is bad/unavailable.
		initialTimeout = 3 * time.Second
	}

	var ret struct {
		AppStatusEmbed
		RandomPassphrase bool `json:"random_pw"`
	}
	err = mctx.G().API.GetDecode(mctx, APIArg{
		Endpoint:       "user/has_random_pw",
		SessionType:    APISessionTypeREQUIRED,
		InitialTimeout: initialTimeout,
	}, &ret)
	if err != nil {
		return passphraseState, err
	}
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
