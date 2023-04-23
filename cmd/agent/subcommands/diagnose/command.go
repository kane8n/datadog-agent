// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package diagnose implements 'agent diagnose'.
package diagnose

import (
	"fmt"
	"os"
	"regexp"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/cmd/agent/command"
	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/log"
	"github.com/DataDog/datadog-agent/pkg/api/util"
	pkgconfig "github.com/DataDog/datadog-agent/pkg/config"
	pkgdiagnose "github.com/DataDog/datadog-agent/pkg/diagnose"
	"github.com/DataDog/datadog-agent/pkg/diagnose/connectivity"
	"github.com/DataDog/datadog-agent/pkg/diagnose/diagnosis"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	utillog "github.com/DataDog/datadog-agent/pkg/util/log"

	"github.com/cihub/seelog"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const (
	metadataEndpoint = "/agent/metadata/"
)

// cliParams are the command-line arguments for this subcommand
type cliParams struct {
	*command.GlobalParams

	// verbose will show details not only failed diagnosis but also succesfull diagnosis
	// it is the, value of the --verbose flag
	verbose bool

	// run as current user, value of the --run-as-user flag
	runAsUser bool

	// run diagnose on other processes, value of --remote-diagnose flag
	remoteDiagnose bool

	// noTrace is the value of the --no-trace flag
	noTrace bool

	// payloadName is the name of the payload to display
	payloadName string

	// diagnose suites to run as a list of regular expressions
	include []string

	// diagnose suites not to run as a list of regular expressions
	exclude []string
}

// Commands returns a slice of subcommands for the 'agent' command.
func Commands(globalParams *command.GlobalParams) []*cobra.Command {
	cliParams := &cliParams{
		GlobalParams: globalParams,
	}

	diagnoseAllCommand := &cobra.Command{
		Use:   "all",
		Short: "Validate Agent installation, configuration and environment",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			utillog.SetupLogger(seelog.Disabled, "off")
			return fxutil.OneShot(runAll,
				fx.Supply(cliParams),
				fx.Supply(core.BundleParams{
					ConfigParams: config.NewAgentParamsWithoutSecrets(globalParams.ConfFilePath),
					LogParams:    log.LogForOneShot("CORE", "off", true)}),
				core.Bundle,
			)
		},
	}

	diagnoseAllCommand.PersistentFlags().BoolVarP(&cliParams.verbose, "verbose", "v", false, "verbose output, includes passed diagnoses, and diagnoses description")
	diagnoseAllCommand.PersistentFlags().BoolVarP(&cliParams.runAsUser, "run-as-user", "u", false, "run as current user")
	diagnoseAllCommand.PersistentFlags().BoolVarP(&cliParams.remoteDiagnose, "remote-diag", "r", false, "collect diagnoses from other agent processes")
	diagnoseAllCommand.PersistentFlags().StringSliceVarP(&cliParams.include, "include", "i", []string{}, "diagnose suites to run as a list of regular expressions")
	diagnoseAllCommand.PersistentFlags().StringSliceVarP(&cliParams.exclude, "exclude", "e", []string{}, "diagnose suites not to run as a list of regular expressions")

	diagnoseMetadataAvailabilityCommand := &cobra.Command{
		Use:   "metadata-availability",
		Short: "Check availability of cloud provider and container metadata endpoints",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fxutil.OneShot(runMetadataAvailability,
				fx.Supply(cliParams),
				fx.Supply(core.BundleParams{
					ConfigParams: config.NewAgentParamsWithoutSecrets(globalParams.ConfFilePath),
					LogParams:    log.LogForOneShot("CORE", "info", true)}),
				core.Bundle,
			)
		},
	}

	diagnoseDatadogConnectivityCommand := &cobra.Command{
		Use:   "datadog-connectivity",
		Short: "Check connectivity between your system and Datadog endpoints",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fxutil.OneShot(runDatadogConnectivityDiagnose,
				fx.Supply(cliParams),
				fx.Supply(core.BundleParams{
					ConfigParams: config.NewAgentParamsWithoutSecrets(globalParams.ConfFilePath),
					LogParams:    log.LogForOneShot("CORE", "info", true)}),
				core.Bundle,
			)
		},
	}
	diagnoseDatadogConnectivityCommand.PersistentFlags().BoolVarP(&cliParams.noTrace, "no-trace", "", false, "mute extra information about connection establishment, DNS lookup and TLS handshake")

	showPayloadCommand := &cobra.Command{
		Use:   "show-metadata",
		Short: "Print metadata payloads sent by the agent",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Help() //nolint:errcheck
			os.Exit(0)
			return nil
		},
	}

	payloadV5Cmd := &cobra.Command{
		Use:   "v5",
		Short: "Print the metadata payload for the agent.",
		Long: `
This command print the V5 metadata payload for the Agent. This payload is used to populate the infra list and host map in Datadog. It's called 'V5' because it's the same payload sent since Agent V5. This payload is mandatory in order to create a new host in Datadog.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliParams.payloadName = "v5"
			return fxutil.OneShot(printPayload,
				fx.Supply(cliParams),
				fx.Supply(core.BundleParams{
					ConfigParams: config.NewAgentParamsWithoutSecrets(globalParams.ConfFilePath),
					LogParams:    log.LogForOneShot("CORE", "off", true)}),
				core.Bundle,
			)
		},
	}

	payloadInventoriesCmd := &cobra.Command{
		Use:   "inventory",
		Short: "Print the Inventory metadata payload for the agent.",
		Long: `
This command print the last Inventory metadata payload sent by the Agent. This payload is used by the 'inventories/sql' product.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliParams.payloadName = "inventory"
			return fxutil.OneShot(printPayload,
				fx.Supply(cliParams),
				fx.Supply(core.BundleParams{
					ConfigParams: config.NewAgentParamsWithoutSecrets(globalParams.ConfFilePath),
					LogParams:    log.LogForOneShot("CORE", "off", true)}),
				core.Bundle,
			)
		},
	}
	showPayloadCommand.AddCommand(payloadV5Cmd)
	showPayloadCommand.AddCommand(payloadInventoriesCmd)

	diagnoseCommand := &cobra.Command{
		Use:   "diagnose",
		Short: "Validate Agent installation, configuration and environment",
		Long:  ``,
		RunE:  diagnoseAllCommand.RunE, // default to 'diagnose all'
	}

	diagnoseCommand.AddCommand(diagnoseAllCommand)
	diagnoseCommand.AddCommand(diagnoseMetadataAvailabilityCommand)
	diagnoseCommand.AddCommand(diagnoseDatadogConnectivityCommand)
	diagnoseCommand.AddCommand(showPayloadCommand)

	return []*cobra.Command{diagnoseCommand}
}

func runAll(log log.Component, config config.Component, cliParams *cliParams) error {
	cfg := diagnosis.DiagnoseConfig{
		Verbose:        cliParams.verbose,
		RunAsUser:      cliParams.runAsUser,
		RemoteDiagnose: cliParams.remoteDiagnose,
	}

	if len(cliParams.include) > 0 {
		cfg.Include = make([]*regexp.Regexp, len(cliParams.include))
		for i, pattern := range cliParams.include {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("failed to compile include regex pattern %s: %s", pattern, err.Error())
			}
			cfg.Include[i] = re
		}
	}

	if len(cliParams.exclude) > 0 {
		cfg.Exclude = make([]*regexp.Regexp, len(cliParams.exclude))
		for i, pattern := range cliParams.exclude {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("failed to compile exclude regex pattern %s: %s", pattern, err.Error())
			}
			cfg.Exclude[i] = re
		}
	}

	return pkgdiagnose.RunAll(color.Output, cfg)
}

func runMetadataAvailability(log log.Component, config config.Component, cliParams *cliParams) error {
	return pkgdiagnose.RunMetadataAvail(color.Output)
}

func runDatadogConnectivityDiagnose(log log.Component, config config.Component, cliParams *cliParams) error {
	return connectivity.RunDatadogConnectivityDiagnose(color.Output, cliParams.noTrace)
}

func printPayload(log log.Component, config config.Component, cliParams *cliParams) error {
	if err := util.SetAuthToken(); err != nil {
		fmt.Println(err)
		return nil
	}

	c := util.GetClient(false)
	ipcAddress, err := pkgconfig.GetIPCAddress()
	if err != nil {
		return err
	}
	apiConfigURL := fmt.Sprintf("https://%v:%d%s%s",
		ipcAddress, config.GetInt("cmd_port"), metadataEndpoint, cliParams.payloadName)

	r, err := util.DoGet(c, apiConfigURL, util.CloseConnection)
	if err != nil {
		return fmt.Errorf("Could not fetch metadata v5 payload: %s", err)
	}

	fmt.Println(string(r))
	return nil
}
