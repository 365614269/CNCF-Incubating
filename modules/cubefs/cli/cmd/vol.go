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
	"sort"
	"strconv"
	"strings"

	"github.com/cubefs/cubefs/proto"
	"github.com/cubefs/cubefs/sdk/master"
	"github.com/cubefs/cubefs/util"
	"github.com/spf13/cobra"
)

const (
	cmdVolUse   = "volume [COMMAND]"
	cmdVolShort = "Manage cluster volumes"
)

func newVolCmd(client *master.MasterClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:     cmdVolUse,
		Short:   cmdVolShort,
		Args:    cobra.MinimumNArgs(0),
		Aliases: []string{"vol"},
	}
	cmd.AddCommand(
		newVolListCmd(client),
		newVolCreateCmd(client),
		newVolExpandCmd(client),
		newVolShrinkCmd(client),
		newVolUpdateCmd(client),
		newVolInfoCmd(client),
		newVolDeleteCmd(client),
		newVolTransferCmd(client),
		newVolAddDPCmd(client),
		newVolAddMPCmd(client),
		newVolSetForbiddenCmd(client),
		newVolSetAuditLogCmd(client),
	)
	return cmd
}

const (
	cmdVolListShort = "List cluster volumes"
)

func newVolListCmd(client *master.MasterClient) *cobra.Command {
	var optKeyword string
	cmd := &cobra.Command{
		Use:     CliOpList,
		Short:   cmdVolListShort,
		Aliases: []string{"ls"},
		Run: func(cmd *cobra.Command, args []string) {
			var vols []*proto.VolInfo
			var err error
			defer func() {
				errout(err)
			}()
			if vols, err = client.AdminAPI().ListVols(optKeyword); err != nil {
				return
			}
			stdout("%v\n", volumeInfoTableHeader)
			for _, vol := range vols {
				stdout("%v\n", formatVolInfoTableRow(vol))
			}
		},
	}
	cmd.Flags().StringVar(&optKeyword, "keyword", "", "Specify keyword of volume name to filter")
	return cmd
}

const (
	cmdVolCreateUse                    = "create [VOLUME NAME] [USER ID]"
	cmdVolCreateShort                  = "Create a new volume"
	cmdVolDefaultMPCount               = 3
	cmdVolDefaultDPCount               = 10
	cmdVolDefaultDPSize                = 120
	cmdVolDefaultCapacity              = 10 // 100GB
	cmdVolDefaultZoneName              = ""
	cmdVolDefaultCrossZone             = "false"
	cmdVolDefaultBusiness              = ""
	cmdVolDefaultVolType               = 0
	cmdVolDefaultCacheRuleKey          = ""
	cmdVolDefaultEbsBlkSize            = 8 * 1024 * 1024
	cmdVolDefaultCacheCapacity         = 0
	cmdVolDefaultCacheAction           = 0
	cmdVolDefaultCacheThreshold        = 10 * 1024 * 1024
	cmdVolDefaultCacheTTL              = 30
	cmdVolDefaultCacheHighWater        = 80
	cmdVolDefaultCacheLowWater         = 60
	cmdVolDefaultCacheLRUInterval      = 5
	cmdVolDefaultDpReadOnlyWhenVolFull = "false"
)

func newVolCreateCmd(client *master.MasterClient) *cobra.Command {
	var optCapacity uint64
	var optCrossZone string
	var optNormalZonesFirst string
	var optBusiness string
	var optMPCount int
	var optDPCount int
	var optReplicaNum string
	var optDPSize int
	var optVolType int
	var optFollowerRead string
	var optZoneName string
	var optCacheRuleKey string
	var optEbsBlkSize int
	var optCacheCap int
	var optCacheAction int
	var optCacheThreshold int
	var optCacheTTL int
	var optCacheHighWater int
	var optCacheLowWater int
	var optCacheLRUInterval int
	var optDpReadOnlyWhenVolFull string
	var optEnableQuota string
	var optTxMask string
	var optTxTimeout uint32
	var optTxConflictRetryNum int64
	var optTxConflictRetryInterval int64
	var optDeleteLockTime int64
	var clientIDKey string
	var optYes bool
	cmd := &cobra.Command{
		Use:   cmdVolCreateUse,
		Short: cmdVolCreateShort,
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			volumeName := args[0]
			userID := args[1]
			defer func() {
				errout(err)
			}()
			crossZone, _ := strconv.ParseBool(optCrossZone)
			followerRead, _ := strconv.ParseBool(optFollowerRead)
			normalZonesFirst, _ := strconv.ParseBool(optNormalZonesFirst)

			if optReplicaNum == "" && optVolType == 1 {
				optReplicaNum = "1"
			}
			if optVolType != 1 && optFollowerRead == "" && (optReplicaNum == "1" || optReplicaNum == "2") {
				followerRead = true
			}
			if optEnableQuota != "yes" {
				optEnableQuota = "false"
			}
			dpReadOnlyWhenVolFull, _ := strconv.ParseBool(optDpReadOnlyWhenVolFull)
			replicaNum, _ := strconv.Atoi(optReplicaNum)

			if optDeleteLockTime < 0 {
				optDeleteLockTime = 0
			}

			// ask user for confirm
			if !optYes {
				stdout("Create a new volume:\n")
				stdout("  Name                     : %v\n", volumeName)
				stdout("  Owner                    : %v\n", userID)
				stdout("  capacity                 : %v G\n", optCapacity)
				stdout("  deleteLockTime           : %v h\n", optDeleteLockTime)
				stdout("  crossZone                : %v\n", crossZone)
				stdout("  DefaultPriority          : %v\n", normalZonesFirst)
				stdout("  description              : %v\n", optBusiness)
				stdout("  mpCount                  : %v\n", optMPCount)
				stdout("  dpCount                  : %v\n", optDPCount)
				stdout("  replicaNum               : %v\n", optReplicaNum)
				stdout("  dpSize                   : %v G\n", optDPSize)
				stdout("  volType                  : %v\n", optVolType)
				stdout("  followerRead             : %v\n", followerRead)
				stdout("  readOnlyWhenFull         : %v\n", dpReadOnlyWhenVolFull)
				stdout("  zoneName                 : %v\n", optZoneName)
				stdout("  cacheRuleKey             : %v\n", optCacheRuleKey)
				stdout("  ebsBlkSize               : %v byte\n", optEbsBlkSize)
				stdout("  cacheCapacity            : %v G\n", optCacheCap)
				stdout("  cacheAction              : %v\n", optCacheAction)
				stdout("  cacheThreshold           : %v byte\n", optCacheThreshold)
				stdout("  cacheTTL                 : %v day\n", optCacheTTL)
				stdout("  cacheHighWater           : %v\n", optCacheHighWater)
				stdout("  cacheLowWater            : %v\n", optCacheLowWater)
				stdout("  cacheLRUInterval         : %v min\n", optCacheLRUInterval)
				stdout("  TransactionMask          : %v\n", optTxMask)
				stdout("  TransactionTimeout       : %v min\n", optTxTimeout)
				stdout("  TxConflictRetryNum       : %v\n", optTxConflictRetryNum)
				stdout("  TxConflictRetryInterval  : %v ms\n", optTxConflictRetryInterval)
				stdout("\nConfirm (yes/no)[yes]: ")
				var userConfirm string
				_, _ = fmt.Scanln(&userConfirm)
				if userConfirm != "yes" && len(userConfirm) != 0 {
					err = fmt.Errorf("Abort by user.\n")
					return
				}
			}

			err = client.AdminAPI().CreateVolName(
				volumeName, userID, optCapacity, optDeleteLockTime, crossZone, normalZonesFirst, optBusiness,
				optMPCount, optDPCount, int(replicaNum), optDPSize, optVolType, followerRead,
				optZoneName, optCacheRuleKey, optEbsBlkSize, optCacheCap,
				optCacheAction, optCacheThreshold, optCacheTTL, optCacheHighWater,
				optCacheLowWater, optCacheLRUInterval, dpReadOnlyWhenVolFull,
				optTxMask, optTxTimeout, optTxConflictRetryNum, optTxConflictRetryInterval, optEnableQuota, clientIDKey)
			if err != nil {
				err = fmt.Errorf("Create volume failed case:\n%v\n", err)
				return
			}
			stdout("Create volume success.\n")
		},
	}
	cmd.Flags().Uint64Var(&optCapacity, CliFlagCapacity, cmdVolDefaultCapacity, "Specify volume capacity")
	cmd.Flags().StringVar(&optCrossZone, CliFlagCrossZone, cmdVolDefaultCrossZone, "Disable cross zone")
	cmd.Flags().StringVar(&optNormalZonesFirst, CliNormalZonesFirst, cmdVolDefaultCrossZone, "Write to normal zone first")
	cmd.Flags().StringVar(&optBusiness, CliFlagBusiness, cmdVolDefaultBusiness, "Description")
	cmd.Flags().IntVar(&optMPCount, CliFlagMPCount, cmdVolDefaultMPCount, "Specify init meta partition count")
	cmd.Flags().IntVar(&optDPCount, CliFlagDPCount, cmdVolDefaultDPCount, "Specify init data partition count")
	cmd.Flags().StringVar(&optReplicaNum, CliFlagReplicaNum, "", "Specify data partition replicas number(default 3 for normal volume,1 for low volume)")
	cmd.Flags().IntVar(&optDPSize, CliFlagDataPartitionSize, cmdVolDefaultDPSize, "Specify data partition size[Unit: GB]")
	cmd.Flags().IntVar(&optVolType, CliFlagVolType, cmdVolDefaultVolType, "Type of volume (default 0)")
	cmd.Flags().StringVar(&optFollowerRead, CliFlagFollowerRead, "", "Enable read form replica follower")
	cmd.Flags().StringVar(&optZoneName, CliFlagZoneName, cmdVolDefaultZoneName, "Specify volume zone name")
	cmd.Flags().StringVar(&optCacheRuleKey, CliFlagCacheRuleKey, cmdVolDefaultCacheRuleKey, "Anything that match this field will be written to the cache")
	cmd.Flags().IntVar(&optEbsBlkSize, CliFlagEbsBlkSize, cmdVolDefaultEbsBlkSize, "Specify ebsBlk Size[Unit: byte]")
	cmd.Flags().IntVar(&optCacheCap, CliFlagCacheCapacity, cmdVolDefaultCacheCapacity, "Specify low volume capacity[Unit: GB]")
	cmd.Flags().IntVar(&optCacheAction, CliFlagCacheAction, cmdVolDefaultCacheAction, "Specify low volume cacheAction (default 0)")
	cmd.Flags().IntVar(&optCacheThreshold, CliFlagCacheThreshold, cmdVolDefaultCacheThreshold, "Specify cache threshold[Unit: byte]")
	cmd.Flags().IntVar(&optCacheTTL, CliFlagCacheTTL, cmdVolDefaultCacheTTL, "Specify cache expiration time[Unit: day]")
	cmd.Flags().IntVar(&optCacheHighWater, CliFlagCacheHighWater, cmdVolDefaultCacheHighWater, "")
	cmd.Flags().IntVar(&optCacheLowWater, CliFlagCacheLowWater, cmdVolDefaultCacheLowWater, "")
	cmd.Flags().IntVar(&optCacheLRUInterval, CliFlagCacheLRUInterval, cmdVolDefaultCacheLRUInterval, "Specify interval expiration time[Unit: min]")
	cmd.Flags().StringVar(&optDpReadOnlyWhenVolFull, CliDpReadOnlyWhenVolFull, cmdVolDefaultDpReadOnlyWhenVolFull,
		"Enable volume becomes read only when it is full")
	cmd.Flags().StringVar(&clientIDKey, CliFlagClientIDKey, client.ClientIDKey(), CliUsageClientIDKey)
	cmd.Flags().BoolVarP(&optYes, "yes", "y", false, "Answer yes for all questions")
	cmd.Flags().StringVar(&optTxMask, CliTxMask, "", "Enable transaction for specified operation: [\"create|mkdir|remove|rename|mknod|symlink|link\"] or \"off\" or \"all\"")
	cmd.Flags().Uint32Var(&optTxTimeout, CliTxTimeout, 1, "Specify timeout[Unit: minute] for transaction [1-60]")
	cmd.Flags().Int64Var(&optTxConflictRetryNum, CliTxConflictRetryNum, 0, "Specify retry times for transaction conflict [1-100]")
	cmd.Flags().Int64Var(&optTxConflictRetryInterval, CliTxConflictRetryInterval, 0, "Specify retry interval[Unit: ms] for transaction conflict [10-1000]")
	cmd.Flags().StringVar(&optEnableQuota, CliFlagEnableQuota, "false", "Enable quota (default false)")
	cmd.Flags().Int64Var(&optDeleteLockTime, CliFlagDeleteLockTime, 0, "Specify delete lock time[Unit: hour] for volume")

	return cmd
}

const (
	cmdVolUpdateShort = "Update configuration of the volume"
)

func newVolUpdateCmd(client *master.MasterClient) *cobra.Command {
	var optDescription string
	var optCacheRule string
	var optZoneName string
	var optCapacity uint64
	var optFollowerRead string
	var optEbsBlkSize int
	var optCacheCap string
	var optCacheAction string
	var optCacheThreshold int
	var optCacheTTL int
	var optCacheHighWater int
	var optCacheLowWater int
	var optCacheLRUInterval int
	var optDpReadOnlyWhenVolFull string
	var clientIDKey string

	var optYes bool
	var optTxMask string
	var optTxTimeout int64
	var optTxForceReset bool
	var optTxConflictRetryNum int64
	var optTxConflictRetryInterval int64
	var optTxOpLimitVal int
	var optReplicaNum string
	var optDeleteLockTime int64
	var optEnableQuota string
	confirmString := strings.Builder{}
	var vv *proto.SimpleVolView
	cmd := &cobra.Command{
		Use:   CliOpUpdate + " [VOLUME NAME]",
		Short: cmdVolUpdateShort,
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			volumeName := args[0]
			isChange := false
			defer func() {
				errout(err)
			}()
			if vv, err = client.AdminAPI().GetVolumeSimpleInfo(volumeName); err != nil {
				return
			}
			confirmString.WriteString("Volume configuration changes:\n")
			confirmString.WriteString(fmt.Sprintf("  Name                : %v\n", vv.Name))
			if optDescription != "" {
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  Description         : %v -> %v \n", vv.Description, optDescription))
				vv.Description = optDescription
			} else {
				confirmString.WriteString(fmt.Sprintf("  Description         : %v \n", vv.Description))
			}
			if !vv.CrossZone && "" != optZoneName {
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  ZoneName            : %v -> %v\n", vv.ZoneName, optZoneName))
				vv.ZoneName = optZoneName
			} else {
				confirmString.WriteString(fmt.Sprintf("  ZoneName            : %v\n", vv.ZoneName))
			}
			if vv.CrossZone && "" != optZoneName {
				err = fmt.Errorf("Can not set zone name of the volume that cross zone\n")
			}
			if optCapacity > 0 {
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  Capacity            : %v GB -> %v GB\n", vv.Capacity, optCapacity))
				vv.Capacity = optCapacity
			} else {
				confirmString.WriteString(fmt.Sprintf("  Capacity            : %v GB\n", vv.Capacity))
			}

			if optReplicaNum != "" {
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  ReplicaNum         : %v -> %v \n", vv.DpReplicaNum, optReplicaNum))
				replicaNum, _ := strconv.ParseUint(optReplicaNum, 10, 8)
				vv.DpReplicaNum = uint8(replicaNum)
			} else {
				confirmString.WriteString(fmt.Sprintf("  ReplicaNum         : %v \n", vv.DpReplicaNum))
			}

			if optFollowerRead != "" {
				isChange = true
				var enable bool
				if enable, err = strconv.ParseBool(optFollowerRead); err != nil {
					return
				}
				confirmString.WriteString(fmt.Sprintf("  Allow follower read : %v -> %v\n", formatEnabledDisabled(vv.FollowerRead), formatEnabledDisabled(enable)))
				vv.FollowerRead = enable
			} else {
				if vv.DpReplicaNum == 1 || vv.DpReplicaNum == 2 {
					vv.FollowerRead = true
				}
				confirmString.WriteString(fmt.Sprintf("  Allow follower read : %v\n", formatEnabledDisabled(vv.FollowerRead)))
			}
			if optEbsBlkSize > 0 {
				if vv.VolType == 0 {
					err = fmt.Errorf("ebs-blk-size not support in hot vol\n")
					return
				}
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  EbsBlkSize          : %v byte -> %v byte\n", vv.ObjBlockSize, optEbsBlkSize))
				vv.ObjBlockSize = optEbsBlkSize
			} else {
				confirmString.WriteString(fmt.Sprintf("  EbsBlkSize          : %v byte\n", vv.ObjBlockSize))
			}
			if optCacheCap != "" {
				if vv.VolType == 0 {
					err = fmt.Errorf("cache-capacity not support in hot vol\n")
					return
				}
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  CacheCap            : %v GB -> %v GB\n", vv.CacheCapacity, optCacheCap))
				intNum, _ := strconv.Atoi(optCacheCap)
				vv.CacheCapacity = uint64(intNum)
			} else {
				confirmString.WriteString(fmt.Sprintf("  CacheCap            : %v GB\n", vv.CacheCapacity))
			}

			if optEnableQuota != "" {
				if optEnableQuota == "false" {
					if vv.EnableQuota {
						isChange = true
						vv.EnableQuota = false
					}
				}
				if optEnableQuota == "true" {
					if !vv.EnableQuota {
						isChange = true
						vv.EnableQuota = true
					}
				}
			}
			confirmString.WriteString(fmt.Sprintf("  EnableQuota : %v\n", formatEnabledDisabled(vv.EnableQuota)))

			if optDeleteLockTime >= 0 {
				if optDeleteLockTime != vv.DeleteLockTime {
					isChange = true
					confirmString.WriteString(fmt.Sprintf("  DeleteLockTime            : %v h -> %v h\n", vv.DeleteLockTime, optDeleteLockTime))
					vv.DeleteLockTime = optDeleteLockTime
				} else {
					confirmString.WriteString(fmt.Sprintf("  DeleteLockTime            : %v h\n", vv.DeleteLockTime))
				}
			} else {
				confirmString.WriteString(fmt.Sprintf("  DeleteLockTime            : %v h\n", vv.DeleteLockTime))
			}

			// var maskStr string
			if optTxMask != "" {
				var oldMask, newMask proto.TxOpMask
				oldMask, err = proto.GetMaskFromString(vv.EnableTransaction)
				if err != nil {
					return
				}
				newMask, err = proto.GetMaskFromString(optTxMask)
				if err != nil {
					return
				}

				if optTxForceReset {
					if oldMask == newMask {
						confirmString.WriteString(fmt.Sprintf("  Transaction Mask    : %v \n", vv.EnableTransaction))
					} else {
						isChange = true
						confirmString.WriteString(fmt.Sprintf("  Transaction Mask    : %v  -> %v \n", vv.EnableTransaction, optTxMask))
					}
				} else {
					if proto.MaskContains(oldMask, newMask) {
						confirmString.WriteString(fmt.Sprintf("  Transaction Mask    : %v \n", vv.EnableTransaction))
					} else {
						isChange = true
						mergedMaskString := ""
						if newMask == proto.TxOpMaskOff {
							mergedMaskString = "off"
						} else {
							mergedMaskString = proto.GetMaskString(oldMask | newMask)
						}

						confirmString.WriteString(fmt.Sprintf("  Transaction Mask    : %v  -> %v \n", vv.EnableTransaction, mergedMaskString))

					}
				}

			} else {
				confirmString.WriteString(fmt.Sprintf("  Transaction Mask    : %v \n", vv.EnableTransaction))
			}

			if optTxTimeout > 0 && vv.TxTimeout != optTxTimeout {
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  Transaction Timeout : %v -> %v\n", vv.TxTimeout, optTxTimeout))
				vv.TxTimeout = optTxTimeout
			} else {
				confirmString.WriteString(fmt.Sprintf("  Transaction Timeout : %v minutes\n", vv.TxTimeout))
			}

			if optTxConflictRetryNum > 0 && vv.TxConflictRetryNum != optTxConflictRetryNum {
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  Tx Conflict Retry Num : %v -> %v\n", vv.TxConflictRetryNum, optTxConflictRetryNum))
				vv.TxConflictRetryNum = optTxConflictRetryNum
			} else {
				confirmString.WriteString(fmt.Sprintf("  Tx Conflict Retry Num : %v\n", vv.TxConflictRetryNum))
			}

			if optTxConflictRetryInterval > 0 && vv.TxConflictRetryInterval != optTxConflictRetryInterval {
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  Tx Conflict Retry Interval : %v -> %v\n", vv.TxConflictRetryInterval, optTxConflictRetryInterval))
				vv.TxConflictRetryInterval = optTxConflictRetryInterval
			} else {
				confirmString.WriteString(fmt.Sprintf("  Tx Conflict Retry Interval : %v ms\n", vv.TxConflictRetryInterval))
			}

			if optTxOpLimitVal > 0 && vv.TxOpLimit != optTxOpLimitVal {
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  Tx Operation limit : %v -> %v\n", vv.TxOpLimit, optTxOpLimitVal))
				vv.TxOpLimit = optTxOpLimitVal
			} else {
				confirmString.WriteString(fmt.Sprintf("  Tx Operation limit : %v\n", vv.TxOpLimit))
			}

			if optCacheAction != "" {
				if vv.VolType == 0 {
					err = fmt.Errorf("cache-action not support in hot vol\n")
					return
				}
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  CacheAction         : %v  -> %v \n", vv.CacheAction, optCacheAction))
				vv.CacheAction, err = strconv.Atoi(optCacheAction)
				if err != nil {
					return
				}
			} else {
				confirmString.WriteString(fmt.Sprintf("  CacheAction         : %v \n", vv.CacheAction))
			}
			if optCacheRule != "" {
				if vv.VolType == 0 {
					err = fmt.Errorf("cache-rule not support in hot vol\n")
					return
				}
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  CacheRule         : %v -> %v \n", vv.CacheRule, optCacheRule))
				vv.CacheRule = optCacheRule
			} else {
				confirmString.WriteString(fmt.Sprintf("  CacheRule        : %v \n", vv.CacheAction))
			}
			if optCacheThreshold > 0 {
				if vv.VolType == 0 {
					err = fmt.Errorf("cache-threshold not support in hot vol\n")
					return
				}
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  CacheThreshold      : %v byte -> %v byte \n", vv.CacheThreshold, optCacheThreshold))
				vv.CacheThreshold = optCacheThreshold
			} else {
				confirmString.WriteString(fmt.Sprintf("  CacheThreshold      : %v byte\n", vv.CacheThreshold))
			}
			if optCacheTTL > 0 {
				if vv.VolType == 0 {
					err = fmt.Errorf("cache-ttl not support in hot vol\n")
					return
				}
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  CacheTTL            : %v day -> %v day \n", vv.CacheTtl, optCacheTTL))
				vv.CacheTtl = optCacheTTL
			} else {
				confirmString.WriteString(fmt.Sprintf("  CacheTTL            : %v day\n", vv.CacheTtl))
			}
			if optCacheHighWater > 0 {
				if vv.VolType == 0 {
					err = fmt.Errorf("cache-high-water not support in hot vol\n")
					return
				}
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  CacheHighWater      : %v  -> %v  \n", vv.CacheHighWater, optCacheHighWater))
				vv.CacheHighWater = optCacheHighWater
			} else {
				confirmString.WriteString(fmt.Sprintf("  CacheHighWater      : %v \n", vv.CacheHighWater))
			}
			if optCacheLowWater > 0 {
				if vv.VolType == 0 {
					err = fmt.Errorf("cache-low-water not support in hot vol\n")
					return
				}
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  CacheLowWater       : %v  -> %v  \n", vv.CacheLowWater, optCacheLowWater))
				vv.CacheLowWater = optCacheLowWater
			} else {
				confirmString.WriteString(fmt.Sprintf("  CacheLowWater       : %v \n", vv.CacheLowWater))
			}
			if optCacheLRUInterval > 0 {
				if vv.VolType == 0 {
					err = fmt.Errorf("cache-lru-interval not support in hot vol\n")
					return
				}
				isChange = true
				confirmString.WriteString(fmt.Sprintf("  CacheLRUInterval    : %v min -> %v min \n", vv.CacheLruInterval, optCacheLRUInterval))
				vv.CacheLruInterval = optCacheLRUInterval
			} else {
				confirmString.WriteString(fmt.Sprintf("  CacheLRUInterval    : %v min\n", vv.CacheLruInterval))
			}
			if optDpReadOnlyWhenVolFull != "" {
				isChange = true
				var enable bool
				if enable, err = strconv.ParseBool(optDpReadOnlyWhenVolFull); err != nil {
					return
				}
				confirmString.WriteString(fmt.Sprintf("  Vol readonly when full : %v -> %v\n",
					formatEnabledDisabled(vv.DpReadOnlyWhenVolFull), formatEnabledDisabled(enable)))
				vv.DpReadOnlyWhenVolFull = enable
			} else {
				confirmString.WriteString(fmt.Sprintf("  Vol readonly full : %v\n",
					formatEnabledDisabled(vv.DpReadOnlyWhenVolFull)))
			}

			if err != nil {
				return
			}
			if !isChange {
				stdout("No changes has been set.\n")
				return
			}
			// ask user for confirm
			if !optYes {
				stdout("%v", confirmString.String())
				stdout("\nConfirm (yes/no)[yes]: ")
				var userConfirm string
				_, _ = fmt.Scanln(&userConfirm)
				if userConfirm != "yes" && len(userConfirm) != 0 {
					err = fmt.Errorf("Abort by user.\n")
					return
				}
			}
			err = client.AdminAPI().UpdateVolume(vv, optTxTimeout, optTxMask, optTxForceReset, optTxConflictRetryNum,
				optTxConflictRetryInterval, optTxOpLimitVal, clientIDKey)
			if err != nil {
				return
			}
			stdout("Volume configuration has been update successfully.\n")
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return validVols(client, toComplete), cobra.ShellCompDirectiveNoFileComp
		},
	}
	cmd.Flags().StringVar(&optDescription, CliFlagDescription, "", "The description of volume")
	cmd.Flags().StringVar(&optZoneName, CliFlagZoneName, "", "Specify volume zone name")
	cmd.Flags().Uint64Var(&optCapacity, CliFlagCapacity, 0, "Specify volume datanode capacity [Unit: GB]")
	cmd.Flags().StringVar(&optFollowerRead, CliFlagEnableFollowerRead, "", "Enable read form replica follower (default false)")
	cmd.Flags().IntVar(&optEbsBlkSize, CliFlagEbsBlkSize, 0, "Specify ebsBlk Size[Unit: byte]")
	cmd.Flags().StringVar(&optCacheCap, CliFlagCacheCapacity, "", "Specify low volume capacity[Unit: GB]")
	cmd.Flags().StringVar(&optCacheAction, CliFlagCacheAction, "", "Specify low volume cacheAction (default 0)")
	cmd.Flags().IntVar(&optCacheThreshold, CliFlagCacheThreshold, 0, "Specify cache threshold[Unit: byte] (default 10M)")
	cmd.Flags().IntVar(&optCacheTTL, CliFlagCacheTTL, 0, "Specify cache expiration time[Unit: day] (default 30)")
	cmd.Flags().IntVar(&optCacheHighWater, CliFlagCacheHighWater, 0, " (default 80)")
	cmd.Flags().IntVar(&optCacheLowWater, CliFlagCacheLowWater, 0, " (default 60)")
	cmd.Flags().StringVar(&optCacheRule, CliFlagCacheRule, "", "Specify cache rule")
	cmd.Flags().IntVar(&optCacheLRUInterval, CliFlagCacheLRUInterval, 0, "Specify interval expiration time[Unit: min] (default 5)")
	cmd.Flags().StringVar(&optDpReadOnlyWhenVolFull, CliDpReadOnlyWhenVolFull, "", "Enable volume becomes read only when it is full")
	cmd.Flags().BoolVarP(&optYes, "yes", "y", false, "Answer yes for all questions")
	cmd.Flags().StringVar(&optTxMask, CliTxMask, "", "Enable transaction for specified operation: [\"create|mkdir|remove|rename|mknod|symlink|link|pause\"] or \"off\" or \"all\"")
	cmd.Flags().Int64Var(&optTxTimeout, CliTxTimeout, 0, "Specify timeout[Unit: minute] for transaction (0-60]")
	cmd.Flags().Int64Var(&optTxConflictRetryNum, CliTxConflictRetryNum, 0, "Specify retry times for transaction conflict [1-100]")
	cmd.Flags().Int64Var(&optTxConflictRetryInterval, CliTxConflictRetryInterval, 0, "Specify retry interval[Unit: ms] for transaction conflict [10-1000]")
	cmd.Flags().BoolVar(&optTxForceReset, CliTxForceReset, false, "Reset transaction mask to the specified value of \"transaction-mask\"")
	cmd.Flags().IntVar(&optTxOpLimitVal, CliTxOpLimit, 0, "Specify limitation[Unit: second] for transaction(default 0 unlimited)")
	cmd.Flags().StringVar(&optReplicaNum, CliFlagReplicaNum, "", "Specify data partition replicas number(default 3 for normal volume,1 for low volume)")
	cmd.Flags().StringVar(&optEnableQuota, CliFlagEnableQuota, "", "Enable quota")
	cmd.Flags().Int64Var(&optDeleteLockTime, CliFlagDeleteLockTime, -1, "Specify delete lock time[Unit: hour] for volume")
	cmd.Flags().StringVar(&clientIDKey, CliFlagClientIDKey, client.ClientIDKey(), CliUsageClientIDKey)

	return cmd
}

const (
	cmdVolInfoUse   = "info [VOLUME NAME]"
	cmdVolInfoShort = "Show volume information"
)

func newVolInfoCmd(client *master.MasterClient) *cobra.Command {
	var (
		optMetaDetail bool
		optDataDetail bool
	)

	cmd := &cobra.Command{
		Use:   cmdVolInfoUse,
		Short: cmdVolInfoShort,
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			volumeName := args[0]
			var svv *proto.SimpleVolView
			defer func() {
				errout(err)
			}()
			if svv, err = client.AdminAPI().GetVolumeSimpleInfo(volumeName); err != nil {
				err = fmt.Errorf("Get volume info failed:\n%v\n", err)
				return
			}
			// print summary info
			stdout("Summary:\n%s\n", formatSimpleVolView(svv))

			// print metadata detail
			if optMetaDetail {
				var views []*proto.MetaPartitionView
				if views, err = client.ClientAPI().GetMetaPartitions(volumeName); err != nil {
					err = fmt.Errorf("Get volume metadata detail information failed:\n%v\n", err)
					return
				}
				stdout("Meta partitions:\n")
				stdout("%v\n", metaPartitionTableHeader)
				sort.SliceStable(views, func(i, j int) bool {
					return views[i].PartitionID < views[j].PartitionID
				})
				for _, view := range views {
					stdout("%v\n", formatMetaPartitionTableRow(view))
				}
			}

			// print data detail
			if optDataDetail {
				var view *proto.DataPartitionsView
				if view, err = client.ClientAPI().EncodingGzip().GetDataPartitions(volumeName); err != nil {
					err = fmt.Errorf("Get volume data detail information failed:\n%v\n", err)
					return
				}
				stdout("Data partitions:\n")
				stdout("%v\n", dataPartitionTableHeader)
				sort.SliceStable(view.DataPartitions, func(i, j int) bool {
					return view.DataPartitions[i].PartitionID < view.DataPartitions[j].PartitionID
				})
				for _, dp := range view.DataPartitions {
					stdout("%v\n", formatDataPartitionTableRow(dp))
				}
			}
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return validVols(client, toComplete), cobra.ShellCompDirectiveNoFileComp
		},
	}
	cmd.Flags().BoolVarP(&optMetaDetail, "meta-partition", "m", false, "Display meta partition detail information")
	cmd.Flags().BoolVarP(&optDataDetail, "data-partition", "d", false, "Display data partition detail information")
	return cmd
}

const (
	cmdVolDeleteUse   = "delete [VOLUME NAME]"
	cmdVolDeleteShort = "Delete a volume from cluster"
)

func newVolDeleteCmd(client *master.MasterClient) *cobra.Command {
	var (
		optYes      bool
		clientIDKey string
		status      bool
	)
	cmd := &cobra.Command{
		Use:   cmdVolDeleteUse,
		Short: cmdVolDeleteShort,
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			volumeName := args[0]
			defer func() {
				errout(err)
			}()
			// ask user for confirm
			if !optYes {
				if status {
					stdout("Delete volume [%v] (yes/no)[no]:", volumeName)
					var userConfirm string
					_, _ = fmt.Scanln(&userConfirm)
					if userConfirm != "yes" {
						err = fmt.Errorf("Abort by user.\n")
						return
					}
				} else {
					stdout("UnDelete volume [%v] (yes/no)[no]:", volumeName)
					var userConfirm string
					_, _ = fmt.Scanln(&userConfirm)
					if userConfirm != "yes" {
						err = fmt.Errorf("Abort by user.\n")
						return
					}
				}
			}

			var svv *proto.SimpleVolView
			svv, err = client.AdminAPI().GetVolumeSimpleInfo(volumeName)
			if status {
				if err != nil {
					err = fmt.Errorf("Delete volume failed:\n%v\n", err)
					return
				}
				if err = client.AdminAPI().DeleteVolumeWithAuthNode(volumeName, util.CalcAuthKey(svv.Owner), clientIDKey); err != nil {
					err = fmt.Errorf("Delete volume failed:\n%v\n", err)
					return
				}
				stdout("Volume has been deleted successfully.\n")
			} else {
				if err != nil {
					err = fmt.Errorf("UnDelete volume failed:\n%v\n", err)
					return
				}
				if err = client.AdminAPI().UnDeleteVolume(volumeName, util.CalcAuthKey(svv.Owner), status); err != nil {
					err = fmt.Errorf("UnDelete volume failed:\n%v\n", err)
					return
				}
				stdout("Volume has been undeleted successfully.\n")
			}
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return validVols(client, toComplete), cobra.ShellCompDirectiveNoFileComp
		},
	}
	cmd.Flags().BoolVarP(&optYes, "yes", "y", false, "Answer yes for all questions")
	cmd.Flags().StringVar(&clientIDKey, CliFlagClientIDKey, client.ClientIDKey(), CliUsageClientIDKey)
	cmd.Flags().BoolVarP(&status, "status", "s", true, "Decide whether to delete or undelete")
	return cmd
}

const (
	cmdVolTransferUse   = "transfer [VOLUME NAME] [USER ID]"
	cmdVolTransferShort = "Transfer volume to another user. (Change owner of volume)"
)

func newVolTransferCmd(client *master.MasterClient) *cobra.Command {
	var optYes bool
	var optForce bool
	var clientIDKey string
	cmd := &cobra.Command{
		Use:     cmdVolTransferUse,
		Short:   cmdVolTransferShort,
		Aliases: []string{"trans"},
		Args:    cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			volume := args[0]
			userID := args[1]

			defer func() {
				errout(err)
			}()

			// ask user for confirm
			if !optYes {
				stdout("Transfer volume [%v] to user [%v] (yes/no)[no]:", volume, userID)
				var confirm string
				_, _ = fmt.Scanln(&confirm)
				if confirm != "yes" {
					err = fmt.Errorf("Abort by user.\n")
					return
				}
			}

			// check target user and volume
			var volSimpleView *proto.SimpleVolView
			if volSimpleView, err = client.AdminAPI().GetVolumeSimpleInfo(volume); err != nil {
				return
			}
			if volSimpleView.Status != 0 {
				err = fmt.Errorf("volume status abnormal")
				return
			}
			var userInfo *proto.UserInfo
			if userInfo, err = client.UserAPI().GetUserInfo(userID); err != nil {
				return
			}
			param := proto.UserTransferVolParam{
				Volume:  volume,
				UserSrc: volSimpleView.Owner,
				UserDst: userInfo.UserID,
				Force:   optForce,
			}
			if _, err = client.UserAPI().TransferVol(&param, clientIDKey); err != nil {
				return
			}
			stdout("Volume has been transferred successfully.\n")
		},
	}
	cmd.Flags().BoolVarP(&optYes, "yes", "y", false, "Answer yes for all questions")
	cmd.Flags().BoolVarP(&optForce, "force", "f", false, "Force transfer without current owner check")
	cmd.Flags().StringVar(&clientIDKey, CliFlagClientIDKey, client.ClientIDKey(), CliUsageClientIDKey)
	return cmd
}

const (
	cmdVolAddDPCmdUse   = "add-dp [VOLUME] [NUMBER]"
	cmdVolAddDPCmdShort = "Create and add more data partition to a volume"
)

func newVolAddDPCmd(client *master.MasterClient) *cobra.Command {
	var clientIDKey string
	cmd := &cobra.Command{
		Use:   cmdVolAddDPCmdUse,
		Short: cmdVolAddDPCmdShort,
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			volume := args[0]
			number := args[1]
			var err error
			defer func() {
				errout(err)
			}()
			var count int64
			if count, err = strconv.ParseInt(number, 10, 64); err != nil {
				return
			}
			if count < 1 {
				err = fmt.Errorf("number must be larger than 0")
				return
			}
			if err = client.AdminAPI().CreateDataPartition(volume, int(count), clientIDKey); err != nil {
				return
			}
			stdout("Add dp successfully.\n")
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return validVols(client, toComplete), cobra.ShellCompDirectiveNoFileComp
		},
	}
	cmd.Flags().StringVar(&clientIDKey, CliFlagClientIDKey, client.ClientIDKey(), CliUsageClientIDKey)
	return cmd
}

const (
	cmdVolAddMPCmdUse   = "add-mp [VOLUME] [NUMBER]"
	cmdVolAddMPCmdShort = "Create and add more meta partition to a volume"
)

func newVolAddMPCmd(client *master.MasterClient) *cobra.Command {
	var clientIDKey string
	cmd := &cobra.Command{
		Use:   cmdVolAddMPCmdUse,
		Short: cmdVolAddMPCmdShort,
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			volume := args[0]
			number := args[1]
			var err error
			defer func() {
				errout(err)
			}()
			var count int64
			if count, err = strconv.ParseInt(number, 10, 64); err != nil {
				return
			}
			if count < 1 {
				err = fmt.Errorf("number must be larger than 0")
				return
			}
			if err = client.AdminAPI().CreateMetaPartition(volume, int(count), clientIDKey); err != nil {
				return
			}
			stdout("Add mp successfully.\n")
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return validVols(client, toComplete), cobra.ShellCompDirectiveNoFileComp
		},
	}
	cmd.Flags().StringVar(&clientIDKey, CliFlagClientIDKey, client.ClientIDKey(), CliUsageClientIDKey)
	return cmd
}

const (
	cmdExpandVolCmdShort = "Expand capacity of a volume"
	cmdShrinkVolCmdShort = "Shrink capacity of a volume"
)

func newVolExpandCmd(client *master.MasterClient) *cobra.Command {
	volClient := NewVolumeClient(OpExpandVol, client)
	return newVolSetCapacityCmd(CliOpExpand, cmdExpandVolCmdShort, volClient)
}

func newVolShrinkCmd(client *master.MasterClient) *cobra.Command {
	volClient := NewVolumeClient(OpShrinkVol, client)
	return newVolSetCapacityCmd(CliOpShrink, cmdShrinkVolCmdShort, volClient)
}

func newVolSetCapacityCmd(use, short string, r clientHandler) *cobra.Command {
	var clientIDKey string
	cmd := &cobra.Command{
		Use:   use + " [VOLUME] [CAPACITY]",
		Short: short,
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			name := args[0]
			capacityStr := args[1]
			var err error
			defer func() {
				errout(err)
			}()
			volume := r.(*volumeClient)
			if volume.capacity, err = strconv.ParseUint(capacityStr, 10, 64); err != nil {
				return
			}
			volume.name = name
			volume.clientIDKey = clientIDKey
			if err = volume.excuteHttp(); err != nil {
				return
			}
			stdout("Volume capacity has been set successfully.\n")
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			volume := r.(*volumeClient)
			return validVols(volume.client, toComplete), cobra.ShellCompDirectiveNoFileComp
		},
	}
	cmd.Flags().StringVar(&clientIDKey, CliFlagClientIDKey, r.(*volumeClient).client.ClientIDKey(), CliUsageClientIDKey)
	return cmd
}

var (
	cmdVolSetForbiddenUse   = "set-forbidden [VOLUME] [FORBIDDEN]"
	cmdVolSetForbiddenShort = "Set the forbidden property for volume"
)

func newVolSetForbiddenCmd(client *master.MasterClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   cmdVolSetForbiddenUse,
		Short: cmdVolSetForbiddenShort,
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			name := args[0]
			settingStr := args[1]
			var err error
			defer func() {
				errout(err)
			}()
			forbidden, err := strconv.ParseBool(settingStr)
			if err != nil {
				return
			}
			if err = client.AdminAPI().SetVolumeForbidden(name, forbidden); err != nil {
				return
			}
			stdout("Volume forbidden property has been set successfully, please wait few minutes for the settings to take effect.\n")
		},
	}
	return cmd
}

var (
	cmdVolSetAuditLogUse   = "set-auditlog [VOLUME] [STATUS]"
	cmdVolSetAuditLogShort = "Enable/Disable backend audit log for volume"
)

func newVolSetAuditLogCmd(client *master.MasterClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   cmdVolSetAuditLogUse,
		Short: cmdVolSetAuditLogShort,
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			name := args[0]
			settingStr := args[1]
			var err error
			defer func() {
				errout(err)
			}()
			enable, err := strconv.ParseBool(settingStr)
			if err != nil {
				return
			}
			if err = client.AdminAPI().SetVolumeAuditLog(name, enable); err != nil {
				return
			}
			stdout("Volume audit log has been set successfully, please wait few minutes for the settings to take effect.\n")
		},
	}
	return cmd
}
