// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/pkg/cmdref"
	clientPkg "github.com/cilium/cilium/pkg/health/client"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

const targetName = "cilium-health"

var (
	client  *clientPkg.Client
	logOpts = make(map[string]string)
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   targetName,
	Short: "Cilium Health Client",
	Long:  `Client for querying the Cilium health status API`,
	Run:   run,
}

// Fatalf prints the Printf formatted message to stderr and exits the program
// Note: os.Exit(1) is not recoverable
func Fatalf(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", fmt.Sprintf(msg, args...))
	os.Exit(1)
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	flags := rootCmd.PersistentFlags()
	flags.BoolP("debug", "D", false, "Enable debug messages")
	flags.StringP("host", "H", "", "URI to cilium-health server API")
	flags.StringSlice("log-driver", []string{}, "Logging endpoints to use for example syslog")
	flags.Var(option.NewNamedMapOptions("log-opts", &logOpts, nil),
		"log-opt", "Log driver options for cilium-health e.g. syslog.level=info,syslog.facility=local5,syslog.tag=cilium-agent")
	viper.BindPFlags(flags)

	rootCmd.AddCommand(cmdref.NewCmd(rootCmd))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.SetEnvPrefix("cilium")
	viper.SetConfigName(".cilium-health") // name of config file (without extension)
	viper.AddConfigPath("$HOME")          // adding home directory as first search path

	if cl, err := clientPkg.NewClient(viper.GetString("host")); err != nil {
		Fatalf("Error while creating client: %s\n", err)
	} else {
		client = cl
	}
}

func run(cmd *cobra.Command, args []string) {
	// Logging should always be bootstrapped first. Do not add any code above this!
	if err := logging.SetupLogging(viper.GetStringSlice("log-driver"), logging.LogOptions(logOpts), "cilium-health", viper.GetBool("debug")); err != nil {
		logging.Fatal(logging.DefaultSlogLogger, "Failed to set up logging", logfields.Error, err)
	}

	cmd.Help()
}
