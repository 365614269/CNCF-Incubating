package ring

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/cortexproject/cortex/pkg/util/backoff"
)

// GetInstanceAddr returns the address to use to register the instance
// in the ring.
func GetInstanceAddr(configAddr string, netInterfaces []string, logger log.Logger) (string, error) {
	if configAddr != "" {
		return configAddr, nil
	}

	addr, err := getFirstAddressOf(netInterfaces, logger)
	if err != nil {
		return "", err
	}

	return addr, nil
}

// GetInstancePort returns the port to use to register the instance
// in the ring.
func GetInstancePort(configPort, listenPort int) int {
	if configPort > 0 {
		return configPort
	}

	return listenPort
}

// WaitInstanceState waits until the input instanceID is registered within the
// ring matching the provided state. A timeout should be provided within the context.
func WaitInstanceState(ctx context.Context, r ReadRing, instanceID string, state InstanceState) error {
	backoff := backoff.New(ctx, backoff.Config{
		MinBackoff: 100 * time.Millisecond,
		MaxBackoff: time.Second,
		MaxRetries: 0,
	})

	for backoff.Ongoing() {
		if actualState, err := r.GetInstanceState(instanceID); err == nil && actualState == state {
			return nil
		}

		backoff.Wait()
	}

	return backoff.Err()
}

// WaitRingStability monitors the ring topology for the provided operation and waits until it
// keeps stable for at least minStability.
func WaitRingStability(ctx context.Context, r *Ring, op Operation, minStability, maxWaiting time.Duration) error {
	return waitStability(ctx, r, op, minStability, maxWaiting, HasReplicationSetChanged)
}

// WaitRingTokensStability waits for the Ring to be unchanged at
// least for minStability time period, excluding transitioning between
// allowed states (e.g. JOINING->ACTIVE if allowed by op).
// This can be used to avoid wasting resources on moving data around
// due to multiple changes in the Ring.
func WaitRingTokensStability(ctx context.Context, r *Ring, op Operation, minStability, maxWaiting time.Duration) error {
	return waitStability(ctx, r, op, minStability, maxWaiting, HasReplicationSetChangedWithoutState)
}

func waitStability(ctx context.Context, r *Ring, op Operation, minStability, maxWaiting time.Duration, isChanged func(ReplicationSet, ReplicationSet) bool) error {
	// Configure the max waiting time as a context deadline.
	ctx, cancel := context.WithTimeout(ctx, maxWaiting)
	defer cancel()

	// Get the initial ring state.
	ringLastState, _ := r.GetAllHealthy(op) // nolint:errcheck
	ringLastStateTs := time.Now()

	const pollingFrequency = time.Second
	pollingTicker := time.NewTicker(pollingFrequency)
	defer pollingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-pollingTicker.C:
			// We ignore the error because in case of error it will return an empty
			// replication set which we use to compare with the previous state.
			currRingState, _ := r.GetAllHealthy(op) // nolint:errcheck

			if isChanged(ringLastState, currRingState) {
				ringLastState = currRingState
				ringLastStateTs = time.Now()
			} else if time.Since(ringLastStateTs) >= minStability {
				return nil
			}
		}
	}
}

// MakeBuffersForGet returns buffers to use with Ring.Get().
func MakeBuffersForGet() (bufDescs []InstanceDesc, bufHosts []string, bufZones map[string]int) {
	bufDescs = make([]InstanceDesc, 0, GetBufferSize)
	bufHosts = make([]string, 0, GetBufferSize)
	bufZones = make(map[string]int, GetZoneSize)
	return
}

func resetZoneMap(zones map[string]int) map[string]int {
	if zones == nil {
		return make(map[string]int, GetZoneSize)
	}

	for key := range zones {
		delete(zones, key)
	}

	return zones
}

// getZones return the list zones from the provided tokens. The returned list
// is guaranteed to be sorted.
func getZones(tokens map[string][]uint32) []string {
	var zones []string

	for zone := range tokens {
		zones = append(zones, zone)
	}

	sort.Strings(zones)
	return zones
}

// searchToken returns the offset of the tokens entry holding the range for the provided key.
func searchToken(tokens []uint32, key uint32) int {
	i := sort.Search(len(tokens), func(x int) bool {
		return tokens[x] > key
	})
	if i >= len(tokens) {
		i = 0
	}
	return i
}

// GetFirstAddressOf returns the first IPv4 address of the supplied interface names, omitting any 169.254.x.x automatic private IPs if possible.
func getFirstAddressOf(names []string, logger log.Logger) (string, error) {
	var ipAddr string
	for _, name := range names {
		inf, err := net.InterfaceByName(name)
		if err != nil {
			level.Warn(logger).Log("msg", "error getting interface", "inf", name, "err", err)
			continue
		}
		addrs, err := inf.Addrs()
		if err != nil {
			level.Warn(logger).Log("msg", "error getting addresses for interface", "inf", name, "err", err)
			continue
		}
		if len(addrs) <= 0 {
			level.Warn(logger).Log("msg", "no addresses found for interface", "inf", name, "err", err)
			continue
		}
		if ip := filterIPs(addrs); ip != "" {
			ipAddr = ip
		}
		if strings.HasPrefix(ipAddr, `169.254.`) || ipAddr == "" {
			continue
		}
		return ipAddr, nil
	}
	if ipAddr == "" {
		return "", fmt.Errorf("no address found for %s", names)
	}
	if strings.HasPrefix(ipAddr, `169.254.`) {
		level.Warn(logger).Log("msg", "using automatic private ip", "address", ipAddr)
	}
	return ipAddr, nil
}

// filterIPs attempts to return the first non automatic private IP (APIPA / 169.254.x.x) if possible, only returning APIPA if available and no other valid IP is found.
func filterIPs(addrs []net.Addr) string {
	var ipAddr string
	for _, addr := range addrs {
		if v, ok := addr.(*net.IPNet); ok {
			if ip := v.IP.To4(); ip != nil {
				ipAddr = v.IP.String()
				if !strings.HasPrefix(ipAddr, `169.254.`) {
					return ipAddr
				}
			}
		}
	}
	return ipAddr
}
