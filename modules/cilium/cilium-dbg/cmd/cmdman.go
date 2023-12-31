// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var dir string

var cmdMan = &cobra.Command{
	Use:   "cmdman",
	Short: "Generate Cilium command reference",
	Run: func(cmd *cobra.Command, args []string) {
		genCmdMan()
	},
	Hidden: true,
}

func genCmdMan() {
	// Remove the line 'Auto generated by spf13/cobra on ...'
	RootCmd.DisableAutoGenTag = true
	header := &doc.GenManHeader{Title: "Cilium", Section: "1"}
	header.Source = "Copyright Authors of Cilium"
	if err := doc.GenManTree(RootCmd, header, dir); err != nil {
		log.Fatal(err)
	}
}

func init() {
	cmdMan.Flags().StringVarP(&dir, "directory", "d", "./", "Path to the output directory")
	RootCmd.AddCommand(cmdMan)
}
