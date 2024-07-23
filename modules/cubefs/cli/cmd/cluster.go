// Copyright 2018 The CubeFS Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cubefs/cubefs/proto"
	"github.com/cubefs/cubefs/sdk/master"
	"github.com/cubefs/cubefs/util/strutil"
	"github.com/spf13/cobra"
)

const (
	cmdClusterUse   = "cluster [COMMAND]"
	cmdClusterShort = "Manage cluster components"
)

func newClusterCmd(client *master.MasterClient) *cobra.Command {
	clusterCmd := &cobra.Command{
		Use:   cmdClusterUse,
		Short: cmdClusterShort,
	}
	clusterCmd.AddCommand(
		newClusterInfoCmd(client),
		newClusterStatCmd(client),
		newClusterFreezeCmd(client),
		newClusterSetThresholdCmd(client),
		newClusterSetParasCmd(client),
		newClusterDisableMpDecommissionCmd(client),
		newClusterSetVolDeletionDelayTimeCmd(client),
		newClusterQueryDecommissionStatusCmd(client),
		newClusterSetDecommissionLimitCmd(client),
		newClusterEnableAutoDecommissionDisk(client),
		newClusterQueryDecommissionFailedDisk(client),
		newClusterEnableAutoDecommissionDiskCmd(client),
		newClusterQueryDecommissionFailedDiskCmd(client),
		newClusterSetDecommissionDiskLimitCmd(client),
	)
	return clusterCmd
}

const (
	cmdClusterInfoShort                    = "Show cluster summary information"
	cmdClusterStatShort                    = "Show cluster status information"
	cmdClusterFreezeShort                  = "Freeze cluster"
	cmdClusterThresholdShort               = "Set memory threshold of metanodes"
	cmdClusterSetClusterInfoShort          = "Set cluster parameters"
	cmdClusterSetVolDeletionDelayTimeShort = "Set volDeletionDelayTime of master"
	nodeDeleteBatchCountKey                = "batchCount"
	nodeMarkDeleteRateKey                  = "markDeleteRate"
	nodeDeleteWorkerSleepMs                = "deleteWorkerSleepMs"
	nodeAutoRepairRateKey                  = "autoRepairRate"
	nodeMaxDpCntLimit                      = "maxDpCntLimit"
	nodeMaxMpCntLimit                      = "maxMpCntLimit"
	cmdForbidMpDecommission                = "forbid meta partition decommission"
	cmdSetDecommissionLimitShort           = "set cluster decommission limit"
	cmdQueryDecommissionStatus             = "query decommission status"
	cmdEnableAutoDecommissionDiskShort     = "enable auto decommission disk"
	cmdQueryDecommissionFailedDiskShort    = "query auto or manual decommission failed disk"
	cmdSetDecommissionDiskLimit            = "set decommission disk limit"
)

func newClusterInfoCmd(client *master.MasterClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   CliOpInfo,
		Short: cmdClusterInfoShort,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			var cv *proto.ClusterView
			var cn *proto.ClusterNodeInfo
			var cp *proto.ClusterIP
			var clusterPara map[string]string
			if cv, err = client.AdminAPI().GetCluster(); err != nil {
				errout(err)
			}
			if cn, err = client.AdminAPI().GetClusterNodeInfo(); err != nil {
				errout(err)
			}
			if cp, err = client.AdminAPI().GetClusterIP(); err != nil {
				errout(err)
			}
			stdout("[Cluster]\n")
			stdout("%v", formatClusterView(cv, cn, cp))
			if clusterPara, err = client.AdminAPI().GetClusterParas(); err != nil {
				errout(err)
			}

			stdout(fmt.Sprintf("  BatchCount         : %v\n", clusterPara[nodeDeleteBatchCountKey]))
			stdout(fmt.Sprintf("  MarkDeleteRate     : %v\n", clusterPara[nodeMarkDeleteRateKey]))
			stdout(fmt.Sprintf("  DeleteWorkerSleepMs: %v\n", clusterPara[nodeDeleteWorkerSleepMs]))
			stdout(fmt.Sprintf("  AutoRepairRate     : %v\n", clusterPara[nodeAutoRepairRateKey]))
			stdout(fmt.Sprintf("  MaxDpCntLimit      : %v\n", clusterPara[nodeMaxDpCntLimit]))
			stdout(fmt.Sprintf("  MaxMpCntLimit      : %v\n", clusterPara[nodeMaxMpCntLimit]))
			stdout("\n")
		},
	}
	return cmd
}

func newClusterStatCmd(client *master.MasterClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   CliOpStatus,
		Short: cmdClusterStatShort,
		Run: func(cmd *cobra.Command, args []string) {
			var (
				err error
				cs  *proto.ClusterStatInfo
			)
			defer func() {
				if err != nil {
					errout(err)
				}
			}()
			if cs, err = client.AdminAPI().GetClusterStat(); err != nil {
				err = fmt.Errorf("Get cluster info fail:\n%v\n", err)
				return
			}
			stdout("[Cluster Status]\n")
			stdout("%v", formatClusterStat(cs))
			stdout("\n")
		},
	}
	return cmd
}

func newClusterFreezeCmd(client *master.MasterClient) *cobra.Command {
	var clientIDKey string
	cmd := &cobra.Command{
		Use:       CliOpFreeze + " [ENABLE]",
		ValidArgs: []string{"true", "false"},
		Short:     cmdClusterFreezeShort,
		Args:      cobra.MinimumNArgs(1),
		Long: `Turn on or off the automatic allocation of the data partitions.
If 'freeze=false', CubeFS WILL automatically allocate new data partitions for the volume when:
  1. the used space is below the max capacity,
  2. and the number of r&w data partition is less than 20.

If 'freeze=true', CubeFS WILL NOT automatically allocate new data partitions `,
		Run: func(cmd *cobra.Command, args []string) {
			var (
				err    error
				enable bool
			)
			defer func() {
				errout(err)
			}()
			if enable, err = strconv.ParseBool(args[0]); err != nil {
				err = fmt.Errorf("Parse bool fail: %v\n", err)
				return
			}
			if err = client.AdminAPI().IsFreezeCluster(enable, clientIDKey); err != nil {
				return
			}
			if enable {
				stdout("Freeze cluster successful!\n")
			} else {
				stdout("Unfreeze cluster successful!\n")
			}
		},
	}
	cmd.Flags().StringVar(&clientIDKey, CliFlagClientIDKey, client.ClientIDKey(), CliUsageClientIDKey)
	return cmd
}

func newClusterSetThresholdCmd(client *master.MasterClient) *cobra.Command {
	var clientIDKey string
	cmd := &cobra.Command{
		Use:   CliOpSetThreshold + " [THRESHOLD]",
		Short: cmdClusterThresholdShort,
		Args:  cobra.MinimumNArgs(1),
		Long: `Set the threshold of memory on each meta node.
If the memory usage reaches this threshold, all the meta partition will be readOnly.`,
		Run: func(cmd *cobra.Command, args []string) {
			var (
				err       error
				threshold float64
			)
			defer func() {
				errout(err)
			}()
			if threshold, err = strconv.ParseFloat(args[0], 64); err != nil {
				err = fmt.Errorf("Parse Float fail: %v\n", err)
				return
			}
			if threshold > 1.0 {
				err = fmt.Errorf("Threshold too big\n")
				return
			}
			if err = client.AdminAPI().SetMetaNodeThreshold(threshold, clientIDKey); err != nil {
				return
			}
			stdout("MetaNode threshold is set to %v!\n", threshold)
		},
	}
	cmd.Flags().StringVar(&clientIDKey, CliFlagClientIDKey, client.ClientIDKey(), CliUsageClientIDKey)
	return cmd
}

func newClusterSetVolDeletionDelayTimeCmd(client *master.MasterClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   CliOpSetVolDeletionDelayTime + " [VOLDELETIONDELAYTIME]",
		Short: cmdClusterSetVolDeletionDelayTimeShort,
		Args:  cobra.MinimumNArgs(1),
		Long:  `Set the volDeletionDelayTime of master on each master.`,
		Run: func(cmd *cobra.Command, args []string) {
			var (
				err                      error
				volDeletionDelayTimeHour int
			)
			defer func() {
				if err != nil {
					errout(err)
				}
			}()
			if volDeletionDelayTimeHour, err = strconv.Atoi(args[0]); err != nil {
				err = fmt.Errorf("Parse int fail: %v\n", err)
				return
			}
			if volDeletionDelayTimeHour <= 0 {
				err = fmt.Errorf("volDeletionDelayTime is less than or equal to 0\n")
				return
			}
			if err = client.AdminAPI().SetMasterVolDeletionDelayTime(volDeletionDelayTimeHour); err != nil {
				return
			}
			stdout("master volDeletionDelayTime is set to %v h!\n", volDeletionDelayTimeHour)
		},
	}
	return cmd
}

func newClusterSetParasCmd(client *master.MasterClient) *cobra.Command {
	var clientIDKey string
	var optAutoRepairRate, optMarkDeleteRate, optDelBatchCount, optDelWorkerSleepMs, optLoadFactor, opMaxDpCntLimit string
	dataNodesetSelector := ""
	metaNodesetSelector := ""
	dataNodeSelector := ""
	metaNodeSelector := ""
	markBrokenDiskThreshold := ""
	autoDpMetaRepair := ""
	opMaxMpCntLimit := ""
	dpRepairTimeout := ""
	dpTimeout := ""
	cmd := &cobra.Command{
		Use:   CliOpSetCluster,
		Short: cmdClusterSetClusterInfoShort,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			defer func() {
				errout(err)
			}()

			if markBrokenDiskThreshold != "" {
				val, err := strutil.ParsePercent(markBrokenDiskThreshold)
				if err != nil {
					return
				}
				markBrokenDiskThreshold = fmt.Sprintf("%v", val)
			}
			if autoDpMetaRepair != "" {
				if _, err = strconv.ParseBool(autoDpMetaRepair); err != nil {
					return
				}
			}

			if dpRepairTimeout != "" {
				var repairTimeout time.Duration
				repairTimeout, err = time.ParseDuration(dpRepairTimeout)
				if err != nil {
					return
				}
				if repairTimeout < time.Second {
					err = fmt.Errorf("dp repair timeout %v smaller than 1s", repairTimeout)
					return
				}

				dpRepairTimeout = strconv.FormatInt(int64(repairTimeout), 10)
			}
			if dpTimeout != "" {
				var heartbeatTimeout time.Duration
				heartbeatTimeout, err = time.ParseDuration(dpTimeout)
				if err != nil {
					return
				}
				if heartbeatTimeout < time.Second {
					err = fmt.Errorf("dp timeout %v smaller than 1s", heartbeatTimeout)
					return
				}

				dpTimeout = strconv.FormatInt(int64(heartbeatTimeout.Seconds()), 10)
			}
			if err = client.AdminAPI().SetClusterParas(optDelBatchCount, optMarkDeleteRate, optDelWorkerSleepMs,
				optAutoRepairRate, optLoadFactor, opMaxDpCntLimit, opMaxMpCntLimit, clientIDKey,
				dataNodesetSelector, metaNodesetSelector,
				dataNodeSelector, metaNodeSelector, markBrokenDiskThreshold, autoDpMetaRepair, dpRepairTimeout, dpTimeout); err != nil {
				return
			}
			stdout("Cluster parameters has been set successfully. \n")
		},
	}
	cmd.Flags().StringVar(&optDelBatchCount, CliFlagDelBatchCount, "", "MetaNode delete batch count")
	cmd.Flags().StringVar(&optLoadFactor, CliFlagLoadFactor, "", "Load Factor")
	cmd.Flags().StringVar(&optMarkDeleteRate, CliFlagMarkDelRate, "", "DataNode batch mark delete limit rate. if 0 for no infinity limit")
	cmd.Flags().StringVar(&optAutoRepairRate, CliFlagAutoRepairRate, "", "DataNode auto repair rate")
	cmd.Flags().StringVar(&optDelWorkerSleepMs, CliFlagDelWorkerSleepMs, "", "MetaNode delete worker sleep time with millisecond. if 0 for no sleep")
	cmd.Flags().StringVar(&opMaxDpCntLimit, CliFlagMaxDpCntLimit, "", "Maximum number of dp on each datanode, default 3000, 0 represents setting to default")
	cmd.Flags().StringVar(&opMaxMpCntLimit, CliFlagMaxMpCntLimit, "", "Maximum number of mp on each metanode, default 300, 0 represents setting to default")
	cmd.Flags().StringVar(&clientIDKey, CliFlagClientIDKey, client.ClientIDKey(), CliUsageClientIDKey)
	cmd.Flags().StringVar(&dataNodesetSelector, CliFlagDataNodesetSelector, "", "Set the nodeset select policy(datanode) for cluster")
	cmd.Flags().StringVar(&metaNodesetSelector, CliFlagMetaNodesetSelector, "", "Set the nodeset select policy(metanode) for cluster")
	cmd.Flags().StringVar(&dataNodeSelector, CliFlagDataNodeSelector, "", "Set the node select policy(datanode) for cluster")
	cmd.Flags().StringVar(&metaNodeSelector, CliFlagMetaNodeSelector, "", "Set the node select policy(metanode) for cluster")
	cmd.Flags().StringVar(&markBrokenDiskThreshold, CliFlagMarkDiskBrokenThreshold, "", "Threshold to mark disk as broken")
	cmd.Flags().StringVar(&autoDpMetaRepair, CliFlagAutoDpMetaRepair, "", "Enable or disable auto data partition meta repair")
	cmd.Flags().StringVar(&dpRepairTimeout, CliFlagDpRepairTimeout, "", "Data partition repair timeout(example: 1h)")
	cmd.Flags().StringVar(&dpTimeout, CliFlagDpTimeout, "", "Data partition heartbeat timeout(example: 10s)")
	return cmd
}

func newClusterDisableMpDecommissionCmd(client *master.MasterClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:       CliOpForbidMpDecommission + " [true|false]",
		ValidArgs: []string{"true", "false"},
		Short:     cmdForbidMpDecommission,
		Args:      cobra.MinimumNArgs(1),
		Long: `Forbid or allow MetaPartition decommission in the cluster.
the forbid flag is false by default when cluster created
If 'forbid=false', MetaPartition decommission/migrate and MetaNode decommission is allowed.
If 'forbid=true', MetaPartition decommission/migrate and MetaNode decommission is forbidden.`,
		Run: func(cmd *cobra.Command, args []string) {
			var (
				err    error
				forbid bool
			)
			defer func() {
				errout(err)
			}()
			if forbid, err = strconv.ParseBool(args[0]); err != nil {
				err = fmt.Errorf("Parse bool fail: %v\n", err)
				return
			}
			if err = client.AdminAPI().SetForbidMpDecommission(forbid); err != nil {
				return
			}
			if forbid {
				stdout("Forbid MetaPartition decommission successful!\n")
			} else {
				stdout("Allow MetaPartition decommission successful!\n")
			}
		},
	}
	return cmd
}

func newClusterSetDecommissionLimitCmd(client *master.MasterClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   CliOpSetDecommissionLimit + " [LIMIT]",
		Short: cmdSetDecommissionLimitShort,
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			defer func() {
				if err != nil {
					errout(err)
				}
			}()
			limit, err := strconv.ParseInt(args[0], 10, 32)
			if err = client.AdminAPI().SetClusterDecommissionLimit(int32(limit)); err != nil {
				return
			}

			stdout("Set decommission limit to %v successfully\n", limit)
		},
	}
	return cmd
}

func newClusterQueryDecommissionStatusCmd(client *master.MasterClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   CliOpQueryDecommissionStatus,
		Short: cmdQueryDecommissionStatus,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			var status []proto.DecommissionTokenStatus
			defer func() {
				if err != nil {
					errout(err)
				}
			}()
			if status, err = client.AdminAPI().QueryDecommissionToken(); err != nil {
				return
			}

			for _, s := range status {
				stdout("%v\n", formatDecommissionTokenStatus(&s))
			}
		},
	}
	return cmd
}

func newClusterEnableAutoDecommissionDiskCmd(client *master.MasterClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:       CliOpEnableAutoDecommission + " [STATUS]",
		ValidArgs: []string{"true", "false"},
		Short:     cmdEnableAutoDecommissionDiskShort,
		Args:      cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var (
				err    error
				enable bool
			)
			defer func() {
				errout(err)
			}()
			if enable, err = strconv.ParseBool(args[0]); err != nil {
				return
			}
			if err = client.AdminAPI().SetAutoDecommissionDisk(enable); err != nil {
				return
			}
			if enable {
				stdout("Enable auto decommission successful!\n")
			} else {
				stdout("Disable auto decommission successful!\n")
			}
		},
	}
	return cmd
}

func newClusterQueryDecommissionFailedDiskCmd(client *master.MasterClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   CliOpQueryDecommissionFailedDisk + " [TYPE]",
		Short: cmdQueryDecommissionFailedDiskShort,
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var (
				err        error
				decommType int
			)

			defer func() {
				errout(err)
			}()

			args[0] = strings.ToLower(args[0])
			if args[0] != "auto" && args[0] != "manual" && args[0] != "all" {
				err = fmt.Errorf("unknown decommission type %v, not \"auto\", \"manual\" and \"and\"", args[0])
				return
			}

			switch args[0] {
			case "manual":
				decommType = 0
			case "auto":
				decommType = 1
			case "all":
				decommType = 2
			}

			diskInfo, err := client.AdminAPI().QueryDecommissionFailedDisk(decommType)
			if err != nil {
				return
			}

			stdout("FailedDisks:\n")
			for i, d := range diskInfo {
				stdout("[%v/%v]\n%v", i+1, len(diskInfo), formatDecommissionFailedDiskInfo(d))
			}
		},
	}
	return cmd
}

func newClusterSetDecommissionDiskLimitCmd(client *master.MasterClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   CliOpSetDecommissionDiskLimit + " [LIMIT]",
		Short: cmdSetDecommissionDiskLimit,
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var (
				err   error
				limit uint32
			)

			defer func() {
				errout(err)
			}()

			tmp, err := strconv.ParseUint(args[0], 10, 32)
			if err != nil {
				return
			}
			limit = uint32(tmp)

			err = client.AdminAPI().SetDecommissionDiskLimit(limit)
			if err != nil {
				return
			}
			stdout("Set decommission disk limit to %v successfully\n", limit)
		},
	}
	return cmd
}

func newClusterEnableAutoDecommissionDisk(client *master.MasterClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:       CliOpEnableAutoDecommission + " [STATUS]",
		ValidArgs: []string{"true", "false"},
		Short:     cmdEnableAutoDecommissionDiskShort,
		Args:      cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var (
				err    error
				enable bool
			)
			defer func() {
				errout(err)
			}()
			if enable, err = strconv.ParseBool(args[0]); err != nil {
				return
			}
			if err = client.AdminAPI().SetAutoDecommissionDisk(enable); err != nil {
				return
			}
			if enable {
				stdout("Enable auto decommission successful!\n")
			} else {
				stdout("Disable auto decommission successful!\n")
			}
		},
	}
	return cmd
}

func newClusterQueryDecommissionFailedDisk(client *master.MasterClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   CliOpQueryDecommissionFailedDisk + " [TYPE]",
		Short: cmdQueryDecommissionFailedDiskShort,
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var (
				err        error
				decommType int
			)

			defer func() {
				errout(err)
			}()

			args[0] = strings.ToLower(args[0])
			if args[0] != "auto" && args[0] != "manual" && args[0] != "all" {
				err = fmt.Errorf("unknown decommission type %v, not \"auto\", \"manual\" and \"and\"", args[0])
				return
			}

			switch args[0] {
			case "manual":
				decommType = 0
			case "auto":
				decommType = 1
			case "all":
				decommType = 2
			}

			diskInfo, err := client.AdminAPI().QueryDecommissionFailedDisk(decommType)
			if err != nil {
				return
			}

			stdout("FailedDisks:\n")
			for i, d := range diskInfo {
				stdout("[%v/%v]\n%v", i+1, len(diskInfo), formatDecommissionFailedDiskInfo(d))
			}
		},
	}
	return cmd
}
