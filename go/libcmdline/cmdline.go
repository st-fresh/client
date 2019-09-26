// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package libcmdline

import (
	"strings"
	"time"

	"github.com/keybase/cli"
	"github.com/keybase/client/go/libkb"
)

type Command interface {
	libkb.Command
	ParseArgv(*cli.Context) error // A command-specific parse-args
	Run() error                   // Run in client mode
}

type ForkCmd int
type LogForward int

const (
	NormalFork ForkCmd = iota
	NoFork
	ForceFork
)

const (
	LogForwardNormal LogForward = iota
	LogForwardNone
)

type CommandLine struct {
	app                   *cli.App
	ctx                   *cli.Context
	cmd                   Command
	name                  string     // the name of the chosen command
	service               bool       // The server is a special command
	fork                  ForkCmd    // If the command is to stop (then don't start the server)
	noStandalone          bool       // On if this command can't run in standalone mode
	logForward            LogForward // What do to about log forwarding
	skipOutOfDateCheck    bool       // don't try to check for service being out of date
	skipAccountResetCheck bool       // don't check if our account is scheduled for rest
	defaultCmd            string
}

func (p CommandLine) IsService() bool             { return p.service }
func (p CommandLine) SkipOutOfDateCheck() bool    { return p.skipOutOfDateCheck }
func (p CommandLine) SkipAccountResetCheck() bool { return p.skipAccountResetCheck }
func (p *CommandLine) SetService()                { p.service = true }
func (p CommandLine) GetForkCmd() ForkCmd         { return p.fork }
func (p *CommandLine) SetForkCmd(v ForkCmd)       { p.fork = v }
func (p *CommandLine) SetNoStandalone()           { p.noStandalone = true }
func (p CommandLine) IsNoStandalone() bool        { return p.noStandalone }
func (p *CommandLine) SetLogForward(f LogForward) { p.logForward = f }
func (p *CommandLine) GetLogForward() LogForward  { return p.logForward }
func (p *CommandLine) SetSkipOutOfDateCheck()     { p.skipOutOfDateCheck = true }
func (p *CommandLine) SetSkipAccountResetCheck()  { p.skipAccountResetCheck = true }

func (p CommandLine) GetNoAutoFork() (bool, bool) {
	return p.GetBool("no-auto-fork", true)
}
func (p CommandLine) GetAutoFork() (bool, bool) {
	return p.GetBool("auto-fork", true)
}
func (p CommandLine) GetHome() string {
	return p.GetGString("home")
}
func (p CommandLine) GetMobileSharedHome() string {
	return p.GetGString("mobile-shared-home")
}
func (p CommandLine) GetServerURI() (string, error) {
	return p.GetGString("server"), nil
}
func (p CommandLine) GetConfigFilename() string {
	return p.GetGString("config-file")
}
func (p CommandLine) GetGUIConfigFilename() string {
	return p.GetGString("gui-config-file")
}
func (p CommandLine) GetUpdaterConfigFilename() string {
	return p.GetGString("updater-config-file")
}
func (p CommandLine) GetDeviceCloneStateFilename() string {
	return p.GetGString("device-clone-state-file")
}
func (p CommandLine) GetSessionFilename() string {
	return p.GetGString("session-file")
}
func (p CommandLine) GetDbFilename() string {
	return p.GetGString("db")
}
func (p CommandLine) GetChatDbFilename() string {
	return p.GetGString("chat-db")
}
func (p CommandLine) GetPvlKitFilename() string {
	return p.GetGString("pvl-kit")
}
func (p CommandLine) GetParamProofKitFilename() string {
	return p.GetGString("paramproof-kit")
}
func (p CommandLine) GetExternalURLKitFilename() string {
	return p.GetGString("externalurl-kit")
}
func (p CommandLine) GetProveBypass() (bool, bool) {
	return p.GetBool("prove-bypass", true)
}
func (p CommandLine) GetDebug() (bool, bool) {
	// --no-debug suppresses --debug. Note that although we don't define a
	// separate GetNoDebug() accessor, fork_server.go still looks for
	// --no-debug by name, to pass it along to an autoforked daemon.
	if noDebug, _ := p.GetBool("no-debug", true); noDebug {
		return false /* val */, true /* isSet */
	}
	return p.GetBool("debug", true)
}
func (p CommandLine) GetDisplayRawUntrustedOutput() (bool, bool) {
	return p.GetBool("display-raw-untrusted-output", true)
}
func (p CommandLine) GetVDebugSetting() string {
	return p.GetGString("vdebug")
}
func (p CommandLine) GetUpgradePerUserKey() (bool, bool) {
	return p.GetBool("upgrade-per-user-key", true)
}
func (p CommandLine) GetPGPFingerprint() *libkb.PGPFingerprint {
	return libkb.PGPFingerprintFromHexNoError(p.GetGString("fingerprint"))
}
func (p CommandLine) GetProxy() string {
	return p.GetGString("proxy")
}
func (p CommandLine) GetLogFile() string {
	return p.GetGString("log-file")
}
func (p CommandLine) GetEKLogFile() string {
	return p.GetGString("ek-log-file")
}
func (p CommandLine) GetGUILogFile() string {
	return p.GetGString("gui-log-file")
}
func (p CommandLine) GetUseDefaultLogFile() (bool, bool) {
	return p.GetBool("use-default-log-file", true)
}
func (p CommandLine) GetUseRootConfigFile() (bool, bool) {
	return p.GetBool("use-root-config-file", true)
}
func (p CommandLine) GetLogPrefix() string {
	return p.GetGString("log-prefix")
}

func (p CommandLine) GetLogFormat() string {
	return p.GetGString("log-format")
}
func (p CommandLine) GetGpgHome() string {
	return p.GetGString("gpg-home")
}
func (p CommandLine) GetAPIDump() (bool, bool) {
	return p.GetBool("api-dump-unsafe", true)
}
func (p CommandLine) GetGregorSaveInterval() (time.Duration, bool) {
	ret, err := p.GetGDuration("push-save-interval")
	if err != nil {
		return 0, false
	}
	return ret, true
}
func (p CommandLine) GetGregorDisabled() (bool, bool) {
	return p.GetBool("push-disabled", true)
}
func (p CommandLine) GetSecretStorePrimingDisabled() (bool, bool) {
	// SecretStorePrimingDisabled is only for tests
	return false, false
}
func (p CommandLine) GetBGIdentifierDisabled() (bool, bool) {
	return p.GetBool("bg-identifier-disabled", true)
}

func (p CommandLine) GetGregorURI() string {
	return p.GetGString("push-server-uri")
}
func (p CommandLine) GetGregorPingInterval() (time.Duration, bool) {
	ret, err := p.GetGDuration("push-ping-interval")
	if err != nil {
		return 0, false
	}
	return ret, true
}
func (p CommandLine) GetGregorPingTimeout() (time.Duration, bool) {
	ret, err := p.GetGDuration("push-ping-timeout")
	if err != nil {
		return 0, false
	}
	return ret, true
}

func (p CommandLine) GetChatDelivererInterval() (time.Duration, bool) {
	ret, err := p.GetGDuration("chat-deliverer-interval")
	if err != nil {
		return 0, false
	}
	return ret, true
}

func (p CommandLine) GetRunMode() (libkb.RunMode, error) {
	return libkb.StringToRunMode(p.GetGString("run-mode"))
}
func (p CommandLine) GetFeatureFlags() (libkb.FeatureFlags, error) {
	return libkb.StringToFeatureFlags(p.GetGString("features")), nil
}
func (p CommandLine) GetPinentry() string {
	return p.GetGString("pinentry")
}
func (p CommandLine) GetAppType() libkb.AppType {
	return libkb.DesktopAppType
}
func (p CommandLine) IsMobileExtension() (bool, bool) {
	return false, false
}
func (p CommandLine) GetSlowGregorConn() (bool, bool) {
	return p.GetBool("slow-gregor-conn", true)
}
func (p CommandLine) GetReadDeletedSigChain() (bool, bool) {
	return p.GetBool("read-deleted-sigchain", true)
}
func (p CommandLine) GetGString(s string) string {
	return p.ctx.GlobalString(s)
}
func (p CommandLine) GetString(s string) string {
	return p.ctx.String(s)
}
func (p CommandLine) GetGInt(s string) int {
	return p.ctx.GlobalInt(s)
}
func (p CommandLine) GetGDuration(s string) (time.Duration, error) {
	return time.ParseDuration(p.GetGString(s))
}
func (p CommandLine) GetGpg() string {
	return p.GetGString("gpg")
}
func (p CommandLine) GetSecretKeyringTemplate() string {
	return p.GetGString("secret-keyring")
}
func (p CommandLine) GetSocketFile() string {
	return p.GetGString("socket-file")
}
func (p CommandLine) GetPidFile() string {
	return p.GetGString("pid-file")
}
func (p CommandLine) GetScraperTimeout() (time.Duration, bool) {
	ret, err := p.GetGDuration("scraper-timeout")
	if err != nil {
		return 0, false
	}
	return ret, true
}
func (p CommandLine) GetAPITimeout() (time.Duration, bool) {
	ret, err := p.GetGDuration("api-timeout")
	if err != nil {
		return 0, false
	}
	return ret, true
}
func (p CommandLine) GetGpgOptions() []string {
	var ret []string
	s := p.GetGString("gpg-options")
	if len(s) > 0 {
		ret = strings.Fields(s)
	}
	return ret
}

func (p CommandLine) getKIDs(name string) []string {
	s := p.GetGString(name)
	if len(s) == 0 {
		return nil
	}
	return strings.Split(s, ":")
}

func (p CommandLine) GetMerkleKIDs() []string {
	return p.getKIDs("merkle-kids")
}

func (p CommandLine) GetCodeSigningKIDs() []string {
	return p.getKIDs("code-signing-kids")
}

func (p CommandLine) GetUserCacheMaxAge() (time.Duration, bool) {
	ret, err := p.GetGDuration("user-cache-maxage")
	if err != nil {
		return 0, false
	}
	return ret, true
}

func (p CommandLine) GetProofCacheSize() (int, bool) {
	ret := p.GetGInt("proof-cache-size")
	if ret != 0 {
		return ret, true
	}
	return 0, false
}

func (p CommandLine) GetLevelDBNumFiles() (int, bool) {
	ret := p.GetGInt("leveldb-num-files")
	if ret != 0 {
		return ret, true
	}
	return 0, false
}

func (p CommandLine) GetChatInboxSourceLocalizeThreads() (int, bool) {
	ret := p.GetGInt("chat-inboxsource-localizethreads")
	if ret != 0 {
		return ret, true
	}
	return 0, false
}

func (p CommandLine) GetLinkCacheSize() (int, bool) {
	ret := p.GetGInt("link-cache-size")
	if ret != 0 {
		return ret, true
	}
	return 0, false
}

func (p CommandLine) GetUPAKCacheSize() (int, bool) {
	ret := p.GetGInt("upak-cache-size")
	if ret != 0 {
		return ret, true
	}
	return 0, false
}

func (p CommandLine) GetUIDMapFullNameCacheSize() (int, bool) {
	ret := p.GetGInt("uid-map-full-name-cache-size")
	if ret != 0 {
		return ret, true
	}
	return 0, false
}

func (p CommandLine) GetPayloadCacheSize() (int, bool) {
	ret := p.GetGInt("payload-cache-size")
	if ret != 0 {
		return ret, true
	}
	return 0, false
}

func (p CommandLine) GetLocalTrackMaxAge() (time.Duration, bool) {
	ret, err := p.GetGDuration("local-track-maxage")
	if err != nil {
		return 0, false
	}
	return ret, true
}

func (p CommandLine) GetStandalone() (bool, bool) {
	return p.GetBool("standalone", true)
}

func (p CommandLine) GetLocalRPCDebug() string {
	return p.GetGString("local-rpc-debug-unsafe")
}

func (p CommandLine) GetTimers() string {
	return p.GetGString("timers")
}

func (p CommandLine) GetTorMode() (ret libkb.TorMode, err error) {
	if s := p.GetGString("tor-mode"); s != "" {
		ret, err = libkb.StringToTorMode(s)
	}
	return ret, err
}

func (p CommandLine) GetTorHiddenAddress() string {
	return p.GetGString("tor-hidden-address")
}
func (p CommandLine) GetTorProxy() string {
	return p.GetGString("tor-proxy")
}

func (p CommandLine) GetProxyType() string {
	return p.GetGString("proxy-type")
}

func (p CommandLine) IsCertPinningEnabled() bool {
	r1, _ := p.GetBool("disable-cert-pinning", true)
	// Defaults to false since it is a boolean flag, so just invert it
	return !r1
}

func (p CommandLine) GetMountDir() string {
	return p.GetGString("mountdir")
}

func (p CommandLine) GetMountDirDefault() string {
	return p.GetGString("mountdirdefault")
}

func (p CommandLine) GetRememberPassphrase() (bool, bool) {
	return p.GetBool("remember-passphrase", true)
}

func (p CommandLine) GetAttachmentDisableMulti() (bool, bool) {
	return p.GetBool("attachment-disable-multi", true)
}

func (p CommandLine) GetDisableTeamAuditor() (bool, bool) {
	return p.GetBool("disable-team-auditor", true)
}

func (p CommandLine) GetDisableTeamBoxAuditor() (bool, bool) {
	return p.GetBool("disable-team-box-auditor", true)
}

func (p CommandLine) GetDisableEKBackgroundKeygen() (bool, bool) {
	return p.GetBool("disable-ek-backgorund-keygen", true)
}

func (p CommandLine) GetDisableMerkleAuditor() (bool, bool) {
	return p.GetBool("disable-merkle-auditor", true)
}

func (p CommandLine) GetDisableSearchIndexer() (bool, bool) {
	return p.GetBool("disable-search-indexer", true)
}

func (p CommandLine) GetDisableBgConvLoader() (bool, bool) {
	return p.GetBool("disable-bg-conv-loader", true)
}

func (p CommandLine) GetEnableBotLiteMode() (bool, bool) {
	return p.GetBool("enable-bot-lite-mode", true)
}

func (p CommandLine) GetExtraNetLogging() (bool, bool) {
	return p.GetBool("extra-net-logging", true)
}

func (p CommandLine) GetForceLinuxKeyring() (bool, bool) {
	return p.GetBool("force-linux-keyring", true)
}

func (p CommandLine) GetForceSecretStoreFile() (bool, bool) {
	return false, false // not configurable via command line flags
}

func (p CommandLine) GetRuntimeStatsEnabled() (bool, bool) {
	return false, false
}
