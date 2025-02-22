package storegateway

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/thanos-io/thanos/pkg/pool"
)

type chunkBytesPool struct {
	pool *pool.BucketedPool[byte]

	// Metrics.
	poolByteStats  *prometheus.CounterVec
	poolInUseBytes prometheus.GaugeFunc
}

func newChunkBytesPool(minBucketSize, maxBucketSize int, maxChunkPoolBytes uint64, reg prometheus.Registerer) (*chunkBytesPool, error) {
	upstream, err := pool.NewBucketedPool[byte](minBucketSize, maxBucketSize, 2, maxChunkPoolBytes)
	if err != nil {
		return nil, err
	}

	return &chunkBytesPool{
		pool: upstream,
		poolByteStats: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "cortex_bucket_store_chunk_pool_operation_bytes_total",
			Help: "Total bytes number of bytes pooled by operation.",
		}, []string{"operation", "stats"}),
		poolInUseBytes: promauto.With(reg).NewGaugeFunc(prometheus.GaugeOpts{
			Name: "cortex_bucket_store_chunk_pool_inuse_bytes",
			Help: "Total bytes in use in the chunk pool.",
		}, func() float64 {
			return float64(upstream.UsedBytes())
		}),
	}, nil
}

func (p *chunkBytesPool) Get(sz int) (*[]byte, error) {
	buffer, err := p.pool.Get(sz)
	if err != nil {
		return buffer, err
	}

	p.poolByteStats.WithLabelValues("get", "requested").Add(float64(sz))
	p.poolByteStats.WithLabelValues("get", "cap").Add(float64(cap(*buffer)))

	return buffer, err
}

func (p *chunkBytesPool) Put(b *[]byte) {
	p.poolByteStats.WithLabelValues("put", "len").Add(float64(len(*b)))
	p.poolByteStats.WithLabelValues("put", "cap").Add(float64(cap(*b)))
	p.pool.Put(b)
}
