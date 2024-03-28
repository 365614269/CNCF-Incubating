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

package datanode

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cubefs/cubefs/cmd/common"
	"github.com/cubefs/cubefs/proto"
	"github.com/cubefs/cubefs/raftstore"
	"github.com/cubefs/cubefs/repl"
	masterSDK "github.com/cubefs/cubefs/sdk/master"
	"github.com/cubefs/cubefs/util"
	"github.com/cubefs/cubefs/util/atomicutil"
	"github.com/cubefs/cubefs/util/config"
	"github.com/cubefs/cubefs/util/exporter"
	"github.com/cubefs/cubefs/util/loadutil"
	"github.com/cubefs/cubefs/util/log"

	"github.com/xtaci/smux"
)

var (
	ErrIncorrectStoreType          = errors.New("Incorrect store type")
	ErrNoSpaceToCreatePartition    = errors.New("No disk space to create a data partition")
	ErrNewSpaceManagerFailed       = errors.New("Creater new space manager failed")
	ErrGetMasterDatanodeInfoFailed = errors.New("Failed to get datanode info from master")

	LocalIP, serverPort string
	gConnPool           = util.NewConnectPool()
	// MasterClient        = masterSDK.NewMasterClient(nil, false)
	MasterClient *masterSDK.MasterCLientWithResolver
)

const (
	DefaultZoneName            = proto.DefaultZoneName
	DefaultRaftDir             = "raft"
	DefaultRaftLogsToRetain    = 10 // Count of raft logs per data partition
	DefaultDiskMaxErr          = 1
	DefaultDiskRetainMin       = 5 * util.GB // GB
	DefaultNameResolveInterval = 1           // minutes

	DefaultDiskUnavailableErrorCount          = 5
	DefaultDiskUnavailablePartitionErrorCount = 3
)

const (
	ModuleName = "dataNode"
)

const (
	ConfigKeyLocalIP       = "localIP"         // string
	ConfigKeyPort          = "port"            // int
	ConfigKeyMasterAddr    = "masterAddr"      // array
	ConfigKeyZone          = "zoneName"        // string
	ConfigKeyDisks         = "disks"           // array
	ConfigKeyRaftDir       = "raftDir"         // string
	ConfigKeyRaftHeartbeat = "raftHeartbeat"   // string
	ConfigKeyRaftReplica   = "raftReplica"     // string
	CfgTickInterval        = "tickInterval"    // int
	CfgRaftRecvBufSize     = "raftRecvBufSize" // int

	ConfigKeyDiskPath         = "diskPath"            // string
	configNameResolveInterval = "nameResolveInterval" // int

	/*
	 * Metrics Degrade Level
	 * minus value: turn off metrics collection.
	 * 0 or 1: full metrics.
	 * 2: 1/2 of the metrics will be collected.
	 * 3: 1/3 of the metrics will be collected.
	 * ...
	 */
	CfgMetricsDegrade = "metricsDegrade" // int

	CfgDiskRdonlySpace = "diskRdonlySpace" // int
	// smux Config
	ConfigKeyEnableSmuxClient  = "enableSmuxConnPool" // bool
	ConfigKeySmuxPortShift     = "smuxPortShift"      // int
	ConfigKeySmuxMaxConn       = "smuxMaxConn"        // int
	ConfigKeySmuxStreamPerConn = "smuxStreamPerConn"  // int
	ConfigKeySmuxMaxBuffer     = "smuxMaxBuffer"      // int
	ConfigKeySmuxTotalStream   = "sumxTotalStream"    // int

	// rate limit control enable
	ConfigDiskQosEnable = "diskQosEnable" // bool
	ConfigDiskReadIocc  = "diskReadIocc"  // int
	ConfigDiskReadIops  = "diskReadIops"  // int
	ConfigDiskReadFlow  = "diskReadFlow"  // int
	ConfigDiskWriteIocc = "diskWriteIocc" // int
	ConfigDiskWriteIops = "diskWriteIops" // int
	ConfigDiskWriteFlow = "diskWriteFlow" // int

	ConfigServiceIDKey = "serviceIDKey"

	// disk status becomes unavailable if disk error partition count reaches this value
	ConfigKeyDiskUnavailablePartitionErrorCount = "diskUnavailablePartitionErrorCount"
	// disk read extent limit
	ConfigEnableDiskReadExtentLimit = "enableDiskReadRepairExtentLimit" // bool
)

const cpuSampleDuration = 1 * time.Second

// DataNode defines the structure of a data node.
type DataNode struct {
	space           *SpaceManager
	port            string
	zoneName        string
	clusterID       string
	localIP         string
	bindIp          bool
	localServerAddr string
	nodeID          uint64
	raftDir         string
	raftHeartbeat   string
	raftReplica     string
	raftStore       raftstore.RaftStore
	tickInterval    int
	raftRecvBufSize int
	startTime       int64

	tcpListener net.Listener
	stopC       chan bool

	smuxPortShift      int
	enableSmuxConnPool bool
	smuxConnPool       *util.SmuxConnectPool
	smuxListener       net.Listener
	smuxServerConfig   *smux.Config
	smuxConnPoolConfig *util.SmuxConnPoolConfig

	getRepairConnFunc func(target string) (net.Conn, error)
	putRepairConnFunc func(conn net.Conn, forceClose bool)

	metrics        *DataNodeMetrics
	metricsDegrade int64
	metricsCnt     uint64
	volUpdating    sync.Map // map[string]*verOp2Phase

	control common.Control

	diskQosEnable           bool
	diskQosEnableFromMaster bool
	diskReadIocc            int
	diskReadIops            int
	diskReadFlow            int
	diskWriteIocc           int
	diskWriteIops           int
	diskWriteFlow           int
	dpMaxRepairErrCnt       uint64
	dpRepairTimeOut         uint64
	clusterUuid             string
	clusterUuidEnable       bool
	serviceIDKey            string
	cpuUtil                 atomicutil.Float64
	cpuSamplerDone          chan struct{}

	diskUnavailablePartitionErrorCount uint64 // disk status becomes unavailable when disk error partition count reaches this value
}

type verOp2Phase struct {
	verSeq     uint64
	verPrepare uint64
	status     uint32
	step       uint32
	op         uint8
	sync.Mutex
}

func NewServer() *DataNode {
	return &DataNode{}
}

func (s *DataNode) Start(cfg *config.Config) (err error) {
	runtime.GOMAXPROCS(runtime.NumCPU())
	return s.control.Start(s, cfg, doStart)
}

// Shutdown shuts down the current data node.
func (s *DataNode) Shutdown() {
	s.control.Shutdown(s, doShutdown)
}

// Sync keeps data node in sync.
func (s *DataNode) Sync() {
	s.control.Sync()
}

// Workflow of starting up a data node.
func doStart(server common.Server, cfg *config.Config) (err error) {
	s, ok := server.(*DataNode)
	if !ok {
		return errors.New("Invalid node Type!")
	}

	s.stopC = make(chan bool)

	// parse the config file
	if err = s.parseConfig(cfg); err != nil {
		return
	}

	exporter.Init(ModuleName, cfg)
	s.registerMetrics()
	s.register(cfg)

	// parse the smux config
	if err = s.parseSmuxConfig(cfg); err != nil {
		return
	}
	// connection pool must be created before initSpaceManager
	s.initConnPool()

	// init limit
	initRepairLimit()

	// start the raft server
	if err = s.startRaftServer(cfg); err != nil {
		return
	}

	// create space manager (disk, partition, etc.)
	if err = s.startSpaceManager(cfg); err != nil {
		return
	}

	// check local partition compare with master ,if lack,then not start
	if _, err = s.checkLocalPartitionMatchWithMaster(); err != nil {
		log.LogError(err)
		exporter.Warning(err.Error())
		return
	}

	// tcp listening & tcp connection pool
	if err = s.startTCPService(); err != nil {
		return
	}

	// smux listening & smux connection pool
	if err = s.startSmuxService(cfg); err != nil {
		return
	}

	go s.registerHandler()

	s.scheduleTask()

	// start metrics (LackDpCount, etc.)
	s.startMetrics()

	// start cpu sampler
	s.startCpuSample()
	return
}

func doShutdown(server common.Server) {
	s, ok := server.(*DataNode)
	if !ok {
		return
	}
	s.closeMetrics()
	close(s.stopC)
	s.space.Stop()
	s.stopUpdateNodeInfo()
	s.stopTCPService()
	s.stopRaftServer()
	s.stopSmuxService()
	s.closeSmuxConnPool()
	MasterClient.Stop()
	// stop cpu sample
	close(s.cpuSamplerDone)
}

func (s *DataNode) parseConfig(cfg *config.Config) (err error) {
	var (
		port       string
		regexpPort *regexp.Regexp
	)
	LocalIP = cfg.GetString(ConfigKeyLocalIP)
	port = cfg.GetString(proto.ListenPort)
	s.bindIp = cfg.GetBool(proto.BindIpKey)
	serverPort = port
	if regexpPort, err = regexp.Compile(`^(\d)+$`); err != nil {
		return fmt.Errorf("Err:no port")
	}
	if !regexpPort.MatchString(port) {
		return fmt.Errorf("Err:port must string")
	}
	s.port = port

	/*for _, ip := range cfg.GetSlice(proto.MasterAddr) {
		MasterClient.AddNode(ip.(string))
	}*/

	updateInterval := cfg.GetInt(configNameResolveInterval)
	if updateInterval <= 0 || updateInterval > 60 {
		log.LogWarnf("name resolving interval[1-60] is set to default: %v", DefaultNameResolveInterval)
		updateInterval = DefaultNameResolveInterval
	}

	addrs := cfg.GetSlice(proto.MasterAddr)
	if len(addrs) == 0 {
		return fmt.Errorf("Err:masterAddr unavalid")
	}
	masters := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		masters = append(masters, addr.(string))
	}
	MasterClient = masterSDK.NewMasterCLientWithResolver(masters, false, updateInterval)
	if MasterClient == nil {
		err = fmt.Errorf("parseConfig: masters addrs format err[%v]", masters)
		log.LogErrorf("parseConfig: masters addrs format err[%v]", masters)
		return err
	}
	if err = MasterClient.Start(); err != nil {
		return err
	}

	s.zoneName = cfg.GetString(ConfigKeyZone)
	if s.zoneName == "" {
		s.zoneName = DefaultZoneName
	}
	s.metricsDegrade = cfg.GetInt64(CfgMetricsDegrade)

	s.serviceIDKey = cfg.GetString(ConfigServiceIDKey)

	diskUnavailablePartitionErrorCount := cfg.GetInt64(ConfigKeyDiskUnavailablePartitionErrorCount)
	if diskUnavailablePartitionErrorCount <= 0 || diskUnavailablePartitionErrorCount > 100 {
		diskUnavailablePartitionErrorCount = DefaultDiskUnavailablePartitionErrorCount
		log.LogDebugf("action[parseConfig] ConfigKeyDiskUnavailablePartitionErrorCount(%v) out of range, set as default(%v)",
			diskUnavailablePartitionErrorCount, DefaultDiskUnavailablePartitionErrorCount)
	}
	s.diskUnavailablePartitionErrorCount = uint64(diskUnavailablePartitionErrorCount)
	log.LogDebugf("action[parseConfig] load diskUnavailablePartitionErrorCount(%v)", s.diskUnavailablePartitionErrorCount)

	log.LogDebugf("action[parseConfig] load masterAddrs(%v).", MasterClient.Nodes())
	log.LogDebugf("action[parseConfig] load port(%v).", s.port)
	log.LogDebugf("action[parseConfig] load zoneName(%v).", s.zoneName)
	return
}

func (s *DataNode) initQosLimit(cfg *config.Config) {
	dn := s.space.dataNode
	dn.diskQosEnable = cfg.GetBoolWithDefault(ConfigDiskQosEnable, true)
	dn.diskReadIocc = cfg.GetInt(ConfigDiskReadIocc)
	dn.diskReadIops = cfg.GetInt(ConfigDiskReadIops)
	dn.diskReadFlow = cfg.GetInt(ConfigDiskReadFlow)
	dn.diskWriteIocc = cfg.GetInt(ConfigDiskWriteIocc)
	dn.diskWriteIops = cfg.GetInt(ConfigDiskWriteIops)
	dn.diskWriteFlow = cfg.GetInt(ConfigDiskWriteFlow)
	log.LogWarnf("action[initQosLimit] set qos [%v], read(iocc:%d iops:%d flow:%d) write(iocc:%d iops:%d flow:%d)",
		dn.diskQosEnable, dn.diskReadIocc, dn.diskReadIops, dn.diskReadFlow, dn.diskWriteIocc, dn.diskWriteIops, dn.diskWriteFlow)
}

func (s *DataNode) updateQosLimit() {
	for _, disk := range s.space.disks {
		disk.updateQosLimiter()
	}
}

func (s *DataNode) startSpaceManager(cfg *config.Config) (err error) {
	s.startTime = time.Now().Unix()
	s.space = NewSpaceManager(s)
	if len(strings.TrimSpace(s.port)) == 0 {
		err = ErrNewSpaceManagerFailed
		return
	}

	s.space.SetRaftStore(s.raftStore)
	s.space.SetNodeID(s.nodeID)
	s.space.SetClusterID(s.clusterID)
	s.initQosLimit(cfg)

	diskRdonlySpace := uint64(cfg.GetInt64(CfgDiskRdonlySpace))
	if diskRdonlySpace < DefaultDiskRetainMin {
		diskRdonlySpace = DefaultDiskRetainMin
	}
	diskEnableReadRepairExtentLimit := cfg.GetBoolWithDefault(ConfigEnableDiskReadExtentLimit, false)
	log.LogInfof("startSpaceManager preReserveSpace %d", diskRdonlySpace)

	paths := make([]string, 0)
	diskPath := cfg.GetString(ConfigKeyDiskPath)
	if diskPath != "" {
		paths, err = parseDiskPath(diskPath)
		if err != nil {
			log.LogErrorf("parse diskpath failed, path %s, err %s", diskPath, err.Error())
			return err
		}
	} else {
		for _, p := range cfg.GetSlice(ConfigKeyDisks) {
			paths = append(paths, p.(string))
		}
	}

	var wg sync.WaitGroup
	for _, d := range paths {
		log.LogDebugf("action[startSpaceManager] load disk raw config(%v).", d)

		// format "PATH:RESET_SIZE
		arr := strings.Split(d, ":")
		if len(arr) != 2 {
			return errors.New("Invalid disk configuration. Example: PATH:RESERVE_SIZE")
		}
		path := arr[0]
		fileInfo, err := os.Stat(path)
		if err != nil {
			log.LogErrorf("Stat disk path [%v] error: [%s]", path, err)
			continue
		}
		if !fileInfo.IsDir() {
			return errors.New("Disk path is not dir")
		}
		if s.clusterUuidEnable {
			if err = config.CheckOrStoreClusterUuid(path, s.clusterUuid, false); err != nil {
				log.LogErrorf("CheckOrStoreClusterUuid failed: %v", err)
				return fmt.Errorf("CheckOrStoreClusterUuid failed: %v", err.Error())
			}
		}
		reservedSpace, err := strconv.ParseUint(arr[1], 10, 64)
		if err != nil {
			return fmt.Errorf("Invalid disk reserved space. Error: %s", err.Error())
		}

		if reservedSpace < DefaultDiskRetainMin {
			reservedSpace = DefaultDiskRetainMin
		}

		wg.Add(1)
		go func(wg *sync.WaitGroup, path string, reservedSpace uint64) {
			defer wg.Done()
			s.space.LoadDisk(path, reservedSpace, diskRdonlySpace, DefaultDiskMaxErr, diskEnableReadRepairExtentLimit)
		}(&wg, path, reservedSpace)
	}

	wg.Wait()
	// start async sample
	s.space.StartDiskSample()
	s.updateQosLimit() // load from config
	s.markAllDiskLoaded()
	return nil
}

func (s *DataNode) markAllDiskLoaded() {
	s.space.diskMutex.Lock()
	defer s.space.diskMutex.Unlock()
	s.space.allDisksLoaded = true
}

func (s *DataNode) checkAllDiskLoaded() bool {
	s.space.diskMutex.RLock()
	defer s.space.diskMutex.RUnlock()
	return s.space.allDisksLoaded
}

// execute shell to find all paths
// out: like, /disk1:1024, /disk2:1024
func parseDiskPath(pathStr string) (disks []string, err error) {
	log.LogInfof("parse diskpath, %s", pathStr)

	arr := strings.Split(pathStr, ":")
	if len(arr) != 2 {
		return disks, fmt.Errorf("diskPath cfg should be diskPathPrefix:RESERVE_SIZE")
	}

	shell := fmt.Sprintf("mount | grep %s | awk '{print $3}'", arr[0])
	cmd := exec.Command("/bin/sh", "-c", shell)
	log.LogWarnf("execute diskPath shell, %s", shell)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return disks, fmt.Errorf("execute shell failed, %s", err.Error())
	}

	disks = make([]string, 0)
	lines := bytes.Split(out, []byte("\n"))
	for _, line := range lines {
		str := strings.TrimSpace(string(line))
		if str == "" {
			continue
		}

		disks = append(disks, fmt.Sprintf("%s:%s", string(line), arr[1]))
	}

	return disks, nil
}

// registers the data node on the master to report the information such as IsIPV4 address.
// The startup of a data node will be blocked until the registration succeeds.
func (s *DataNode) register(cfg *config.Config) {
	var err error

	timer := time.NewTimer(0)

	// get the IsIPV4 address, cluster ID and node ID from the master
	for {
		select {
		case <-timer.C:
			var ci *proto.ClusterInfo
			if ci, err = MasterClient.AdminAPI().GetClusterInfo(); err != nil {
				log.LogErrorf("action[registerToMaster] cannot get ip from master(%v) err(%v).",
					MasterClient.Leader(), err)
				timer.Reset(2 * time.Second)
				continue
			}
			masterAddr := MasterClient.Leader()
			s.clusterUuid = ci.ClusterUuid
			s.clusterUuidEnable = ci.ClusterUuidEnable
			s.clusterID = ci.Cluster
			if LocalIP == "" {
				LocalIP = string(ci.Ip)
			}
			s.localServerAddr = fmt.Sprintf("%s:%v", LocalIP, s.port)
			if !util.IsIPV4(LocalIP) {
				log.LogErrorf("action[registerToMaster] got an invalid local ip(%v) from master(%v).",
					LocalIP, masterAddr)
				timer.Reset(2 * time.Second)
				continue
			}

			// register this data node on the master
			var nodeID uint64
			if nodeID, err = MasterClient.NodeAPI().AddDataNodeWithAuthNode(fmt.Sprintf("%s:%v", LocalIP, s.port),
				s.zoneName, s.serviceIDKey); err != nil {
				log.LogErrorf("action[registerToMaster] cannot register this node to master[%v] err(%v).",
					masterAddr, err)
				timer.Reset(2 * time.Second)
				continue
			}
			exporter.RegistConsul(s.clusterID, ModuleName, cfg)
			s.nodeID = nodeID
			log.LogDebugf("register: register DataNode: nodeID(%v)", s.nodeID)
			return
		case <-s.stopC:
			timer.Stop()
			return
		}
	}
}

type DataNodeInfo struct {
	Addr                      string
	PersistenceDataPartitions []uint64
}

func (s *DataNode) checkLocalPartitionMatchWithMaster() (lackPartitions []uint64, err error) {
	convert := func(node *proto.DataNodeInfo) *DataNodeInfo {
		result := &DataNodeInfo{}
		result.Addr = node.Addr
		result.PersistenceDataPartitions = node.PersistenceDataPartitions
		return result
	}
	var dataNode *proto.DataNodeInfo
	for i := 0; i < 3; i++ {
		if dataNode, err = MasterClient.NodeAPI().GetDataNode(s.localServerAddr); err != nil {
			log.LogErrorf("checkLocalPartitionMatchWithMaster error %v", err)
			continue
		}
		break
	}
	if dataNode == nil {
		err = ErrGetMasterDatanodeInfoFailed
		return
	}
	dinfo := convert(dataNode)
	if len(dinfo.PersistenceDataPartitions) == 0 {
		return
	}

	for _, partitionID := range dinfo.PersistenceDataPartitions {
		dp := s.space.Partition(partitionID)
		if dp == nil {
			lackPartitions = append(lackPartitions, partitionID)
		}
	}

	if len(lackPartitions) == 0 {
		log.LogInfo("checkLocalPartitionMatchWithMaster no lack")
	} else {
		log.LogErrorf("checkLocalPartitionMatchWithMaster lack ids [%v]", lackPartitions)
	}
	return
}

func (s *DataNode) checkPartitionInMemoryMatchWithInDisk() (lackPartitions []uint64) {
	s.space.partitionMutex.RLock()
	partitions := make([]*DataPartition, 0)
	for _, dp := range s.space.partitions {
		partitions = append(partitions, dp)
	}
	s.space.partitionMutex.RUnlock()

	for _, dp := range partitions {
		stat, err := os.Stat(dp.path)
		if err != nil {
			lackPartitions = append(lackPartitions, dp.partitionID)
			log.LogErrorf("action[checkPartitionInMemoryMatchWithInDisk] stat dataPartition[%v] fail, path[%v], err[%v]", dp.partitionID, dp.Path(), err)
			continue
		}
		if !stat.IsDir() {
			lackPartitions = append(lackPartitions, dp.partitionID)
			log.LogErrorf("action[checkPartitionInMemoryMatchWithInDisk] dataPartition[%v] is not directory, path[%v]", dp.partitionID, dp.Path())
			continue
		}
	}
	return
}

func (s *DataNode) registerHandler() {
	http.HandleFunc("/disks", s.getDiskAPI)
	http.HandleFunc("/partitions", s.getPartitionsAPI)
	http.HandleFunc("/partition", s.getPartitionAPI)
	http.HandleFunc("/extent", s.getExtentAPI)
	http.HandleFunc("/block", s.getBlockCrcAPI)
	http.HandleFunc("/stats", s.getStatAPI)
	http.HandleFunc("/raftStatus", s.getRaftStatus)
	http.HandleFunc("/setAutoRepairStatus", s.setAutoRepairStatus)
	http.HandleFunc("/getTinyDeleted", s.getTinyDeleted)
	http.HandleFunc("/getNormalDeleted", s.getNormalDeleted)
	http.HandleFunc("/getSmuxPoolStat", s.getSmuxPoolStat())
	http.HandleFunc("/setMetricsDegrade", s.setMetricsDegrade)
	http.HandleFunc("/getMetricsDegrade", s.getMetricsDegrade)
	http.HandleFunc("/qosEnable", s.setQosEnable())
	http.HandleFunc("/genClusterVersionFile", s.genClusterVersionFile)
	http.HandleFunc("/setDiskBad", s.setDiskBadAPI)
	http.HandleFunc("/setDiskQos", s.setDiskQos)
	http.HandleFunc("/getDiskQos", s.getDiskQos)
	http.HandleFunc("/reloadDataPartition", s.reloadDataPartition)
	http.HandleFunc("/setDiskExtentReadLimitStatus", s.setDiskExtentReadLimitStatus)
	http.HandleFunc("/queryDiskExtentReadLimitStatus", s.queryDiskExtentReadLimitStatus)
	// http.HandleFunc("/detachDataPartition", s.detachDataPartition)
	// http.HandleFunc("/loadDataPartition", s.loadDataPartition)
	http.HandleFunc("/releaseDiskExtentReadLimitToken", s.releaseDiskExtentReadLimitToken)
}

func (s *DataNode) startTCPService() (err error) {
	log.LogInfo("Start: startTCPService")
	addr := fmt.Sprintf(":%v", s.port)
	if s.bindIp {
		addr = fmt.Sprintf("%s:%v", LocalIP, s.port)
	}
	l, err := net.Listen(NetworkProtocol, addr)
	log.LogDebugf("action[startTCPService] listen %v address(%v).", NetworkProtocol, addr)
	if err != nil {
		log.LogError("failed to listen, err:", err)
		return
	}
	s.tcpListener = l
	go func(ln net.Listener) {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.LogErrorf("action[startTCPService] failed to accept, err:%s", err.Error())
				break
			}
			log.LogDebugf("action[startTCPService] accept connection from %s.", conn.RemoteAddr().String())
			go s.serveConn(conn)
		}
	}(l)
	return
}

func (s *DataNode) stopTCPService() (err error) {
	if s.tcpListener != nil {

		s.tcpListener.Close()
		log.LogDebugf("action[stopTCPService] stop tcp service.")
	}
	return
}

func (s *DataNode) serveConn(conn net.Conn) {
	space := s.space
	space.Stats().AddConnection()
	c, _ := conn.(*net.TCPConn)
	c.SetKeepAlive(true)
	c.SetNoDelay(true)
	packetProcessor := repl.NewReplProtocol(conn, s.Prepare, s.OperatePacket, s.Post)
	packetProcessor.ServerConn()
	space.Stats().RemoveConnection()
}

func (s *DataNode) startSmuxService(cfg *config.Config) (err error) {
	log.LogInfo("Start: startSmuxService")
	addr := fmt.Sprintf(":%v", s.port)
	if s.bindIp {
		addr = fmt.Sprintf("%s:%v", LocalIP, s.port)
	}
	addr = util.ShiftAddrPort(addr, s.smuxPortShift)
	log.LogInfof("SmuxListenAddr: (%v)", addr)

	// server
	l, err := net.Listen(NetworkProtocol, addr)
	log.LogDebugf("action[startSmuxService] listen %v address(%v).", NetworkProtocol, addr)
	if err != nil {
		log.LogError("failed to listen smux addr, err:", err)
		return
	}
	s.smuxListener = l
	go func(ln net.Listener) {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.LogErrorf("action[startSmuxService] failed to accept, err:%s", err.Error())
				break
			}
			log.LogDebugf("action[startSmuxService] accept connection from %s.", conn.RemoteAddr().String())
			go s.serveSmuxConn(conn)
		}
	}(l)
	return
}

func (s *DataNode) stopSmuxService() (err error) {
	if s.smuxListener != nil {
		s.smuxListener.Close()
		log.LogDebugf("action[stopSmuxService] stop smux service.")
	}
	return
}

func (s *DataNode) serveSmuxConn(conn net.Conn) {
	space := s.space
	space.Stats().AddConnection()
	c, _ := conn.(*net.TCPConn)
	c.SetKeepAlive(true)
	c.SetNoDelay(true)
	var sess *smux.Session
	var err error
	sess, err = smux.Server(conn, s.smuxServerConfig)
	if err != nil {
		log.LogErrorf("action[serveSmuxConn] failed to serve smux connection, addr(%v), err(%v)", c.RemoteAddr(), err)
		return
	}
	defer func() {
		sess.Close()
		space.Stats().RemoveConnection()
	}()
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if util.FilterSmuxAcceptError(err) != nil {
				log.LogErrorf("action[startSmuxService] failed to accept, err: %s", err)
			} else {
				log.LogInfof("action[startSmuxService] accept done, err: %s", err)
			}
			break
		}
		go s.serveSmuxStream(stream)
	}
}

func (s *DataNode) serveSmuxStream(stream *smux.Stream) {
	packetProcessor := repl.NewReplProtocol(stream, s.Prepare, s.OperatePacket, s.Post)
	if s.enableSmuxConnPool {
		packetProcessor.SetSmux(s.getRepairConnFunc, s.putRepairConnFunc)
	}
	packetProcessor.ServerConn()
}

func (s *DataNode) parseSmuxConfig(cfg *config.Config) error {
	s.enableSmuxConnPool = cfg.GetBool(ConfigKeyEnableSmuxClient)
	s.smuxPortShift = int(cfg.GetInt64(ConfigKeySmuxPortShift))
	if s.smuxPortShift == 0 {
		s.smuxPortShift = util.DefaultSmuxPortShift
	}
	// smux server cfg
	s.smuxServerConfig = util.DefaultSmuxConfig()
	maxBuffer := cfg.GetInt64(ConfigKeySmuxMaxBuffer)
	if maxBuffer > 0 {
		s.smuxServerConfig.MaxReceiveBuffer = int(maxBuffer)
		if s.smuxServerConfig.MaxStreamBuffer > int(maxBuffer) {
			s.smuxServerConfig.MaxStreamBuffer = int(maxBuffer)
		}
		if err := smux.VerifyConfig(s.smuxServerConfig); err != nil {
			return err
		}
	}

	// smux conn pool config
	if s.enableSmuxConnPool {
		s.smuxConnPoolConfig = util.DefaultSmuxConnPoolConfig()
		if maxBuffer > 0 {
			s.smuxConnPoolConfig.MaxReceiveBuffer = int(maxBuffer)
			if s.smuxConnPoolConfig.MaxStreamBuffer > int(maxBuffer) {
				s.smuxConnPoolConfig.MaxStreamBuffer = int(maxBuffer)
			}
		}
		maxConn := cfg.GetInt64(ConfigKeySmuxMaxConn)
		if maxConn > 0 {
			if s.smuxConnPoolConfig.ConnsPerAddr < int(maxConn) {
				s.smuxConnPoolConfig.ConnsPerAddr = int(maxConn)
			}
		}
		maxStreamPerConn := cfg.GetInt64(ConfigKeySmuxStreamPerConn)
		if maxStreamPerConn > 0 {
			s.smuxConnPoolConfig.StreamsPerConn = int(maxStreamPerConn)
		}
		totalStreams := cfg.GetInt64(ConfigKeySmuxTotalStream)
		if totalStreams > 0 {
			s.smuxConnPoolConfig.TotalStreams = int(totalStreams)
		}
		if err := util.VerifySmuxPoolConfig(s.smuxConnPoolConfig); err != nil {
			return err
		}
	}
	log.LogDebugf("[parseSmuxConfig] load smuxPortShift(%v).", s.smuxPortShift)
	log.LogDebugf("[parseSmuxConfig] load enableSmuxConnPool(%v).", s.enableSmuxConnPool)
	log.LogDebugf("[parseSmuxConfig] load smuxServerConfig(%v).", s.smuxServerConfig)
	log.LogDebugf("[parseSmuxConfig] load smuxConnPoolConfig(%v).", s.smuxConnPoolConfig)
	return nil
}

func (s *DataNode) initConnPool() {
	if s.enableSmuxConnPool {
		log.LogInfof("Start: init smux conn pool")
		s.smuxConnPool = util.NewSmuxConnectPool(s.smuxConnPoolConfig)
		s.getRepairConnFunc = func(target string) (net.Conn, error) {
			addr := util.ShiftAddrPort(target, s.smuxPortShift)
			log.LogDebugf("[dataNode.getRepairConnFunc] get smux conn, addr(%v)", addr)
			return s.smuxConnPool.GetConnect(addr)
		}
		s.putRepairConnFunc = func(conn net.Conn, forceClose bool) {
			log.LogDebugf("[dataNode.putRepairConnFunc] put smux conn, addr(%v), forceClose(%v)", conn.RemoteAddr().String(), forceClose)
			s.smuxConnPool.PutConnect(conn.(*smux.Stream), forceClose)
		}
	} else {
		s.getRepairConnFunc = func(target string) (conn net.Conn, err error) {
			log.LogDebugf("[dataNode.getRepairConnFunc] get tcp conn, addr(%v)", target)
			return gConnPool.GetConnect(target)
		}
		s.putRepairConnFunc = func(conn net.Conn, forceClose bool) {
			log.LogDebugf("[dataNode.putRepairConnFunc] put tcp conn, addr(%v), forceClose(%v)", conn.RemoteAddr().String(), forceClose)
			gConnPool.PutConnect(conn.(*net.TCPConn), forceClose)
		}
	}
}

func (s *DataNode) closeSmuxConnPool() {
	if s.smuxConnPool != nil {
		s.smuxConnPool.Close()
		log.LogDebugf("action[stopSmuxService] stop smux conn pool")
	}
}

func (s *DataNode) shallDegrade() bool {
	level := atomic.LoadInt64(&s.metricsDegrade)
	if level < 0 {
		return true
	}
	if level == 0 {
		return false
	}
	cnt := atomic.LoadUint64(&s.metricsCnt)
	return cnt%uint64(level) != 0
}

func (s *DataNode) scheduleTask() {
	go s.startUpdateNodeInfo()
	s.scheduleToCheckLackPartitions()
}

func (s *DataNode) startCpuSample() {
	s.cpuSamplerDone = make(chan struct{})
	go func() {
		for {
			select {
			case <-s.cpuSamplerDone:
				return
			default:
				// this function will sleep cpuSampleDuration
				used, err := loadutil.GetCpuUtilPercent(cpuSampleDuration)
				if err == nil {
					s.cpuUtil.Store(used)
				}
			}
		}
	}()
}

func (s *DataNode) scheduleToCheckLackPartitions() {
	go func() {
		for {
			lackPartitionsInMem, err := s.checkLocalPartitionMatchWithMaster()
			if err != nil {
				log.LogError(err)
			}
			if len(lackPartitionsInMem) > 0 {
				err = fmt.Errorf("action[scheduleToLackDataPartitions] lackPartitions %v in datanode %v memory",
					lackPartitionsInMem, s.localServerAddr)
				log.LogErrorf(err.Error())
			}
			s.space.stats.updateMetricLackPartitionsInMem(uint64(len(lackPartitionsInMem)))

			lackPartitionsInDisk := s.checkPartitionInMemoryMatchWithInDisk()
			if len(lackPartitionsInDisk) > 0 {
				err = fmt.Errorf("action[scheduleToLackDataPartitions] lackPartitions %v in datanode %v disk",
					lackPartitionsInDisk, s.localServerAddr)
				log.LogErrorf(err.Error())
			}
			s.space.stats.updateMetricLackPartitionsInDisk(uint64(len(lackPartitionsInDisk)))

			time.Sleep(1 * time.Minute)
		}
	}()
}

func IsDiskErr(errMsg string) bool {
	return strings.Contains(errMsg, syscall.EIO.Error()) ||
		strings.Contains(errMsg, syscall.EROFS.Error()) ||
		strings.Contains(errMsg, syscall.EACCES.Error())
}
