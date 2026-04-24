package main

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/grafana/dskit/concurrency"
	"github.com/schollz/progressbar/v3"
)

// ServiceMapper maps IP addresses to service names using both static configuration and dynamic detection.
type ServiceMapper struct {
	staticMapper  *StaticServiceMapper
	dynamicMapper *DynamicServiceMapper
	logger        Logger

	// memoryCache provides fast in-memory caching.
	memoryCache *ServiceMapperMemoryCache
	// persistentCache provides SQLite-backed persistent storage.
	persistentCache *ServiceMapperPersistentCache
}

// NewServiceMapper creates a new ServiceMapper instance with the provided static and dynamic mappers.
func NewServiceMapper(staticMapper *StaticServiceMapper, dynamicMapper *DynamicServiceMapper, persistentCache *ServiceMapperPersistentCache, logger Logger) *ServiceMapper {
	return &ServiceMapper{
		staticMapper:    staticMapper,
		dynamicMapper:   dynamicMapper,
		logger:          logger,
		memoryCache:     NewServiceMapperMemoryCache(),
		persistentCache: persistentCache,
	}
}

// lookupFromCache performs layered cache lookup: memory first, then persistent cache.
func (sm *ServiceMapper) lookupFromCache(addr string) (string, bool) {
	// Check in-memory cache first.
	if serviceName, found := sm.memoryCache.Lookup(addr); found {
		return serviceName, true
	}

	// Check persistent cache if available.
	if sm.persistentCache != nil {
		if serviceName, found := sm.persistentCache.Lookup(addr); found {
			// Found in persistent cache, promote to memory cache.
			sm.memoryCache.Store(addr, serviceName)
			return serviceName, true
		}
	}

	return "", false
}

// GetServiceNameByAddr returns the service name for a given address, trying static mapper first, then dynamic mapper.
func (sm *ServiceMapper) GetServiceNameByAddr(addr string) string {
	// Check layered cache first.
	if serviceName, found := sm.lookupFromCache(addr); found {
		return serviceName
	}

	// Try static mapper first.
	serviceName := sm.staticMapper.GetServiceNameByAddr(addr)
	if serviceName != "" {
		// Cache only in memory for static mappings.
		sm.memoryCache.Store(addr, serviceName)
		return serviceName
	}

	// Fall back to dynamic mapper for all IPs (both public and private).
	serviceName = sm.dynamicMapper.GetServiceNameByAddr(addr)

	// Cache the result only for public IPs to avoid repeated HTTP requests.
	// Private IPs (like pod IPs) are looked up from in-memory maps, so no caching needed.
	if !isPrivateIP(addr) {
		sm.memoryCache.Store(addr, serviceName)
		if sm.persistentCache != nil {
			sm.persistentCache.Store(addr, serviceName)
		}
	}

	return serviceName
}

// GetServiceNameByAddrs returns a map of addresses to their service names, processing addresses concurrently.
func (sm *ServiceMapper) GetServiceNameByAddrs(addrs []string) map[string]string {
	if len(addrs) == 0 {
		return nil
	}

	totalAddrs := len(addrs)

	bar := progressbar.NewOptions(totalAddrs,
		progressbar.OptionSetWriter(sm.logger.GetWriter()),
		progressbar.OptionSetDescription("Resolving services"),
		progressbar.OptionShowCount(),
		progressbar.OptionShowElapsedTimeOnFinish(),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionSetItsString("addrs"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}))

	result := make(map[string]string)
	resultMx := sync.Mutex{}

	concurrency.ForEachJob(context.Background(), len(addrs), 32, func(ctx context.Context, i int) error {
		addr := addrs[i]
		serviceName := sm.GetServiceNameByAddr(addr)

		resultMx.Lock()
		result[addr] = serviceName

		// Update memory info on progress bar occasionally to avoid too much overhead
		if (i+1)%10 == 0 {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			memoryMB := float64(m.Alloc) / 1024 / 1024
			bar.Describe(fmt.Sprintf("Resolving services (Mem: %.1f MB)", memoryMB))
		}
		resultMx.Unlock()

		bar.Add(1)

		return nil
	})

	bar.Finish()
	fmt.Fprintf(sm.logger.GetWriter(), "\n")
	return result
}

// GetCacheSize returns the number of entries in the memory cache (for testing).
func (sm *ServiceMapper) GetCacheSize() int {
	return sm.memoryCache.Size()
}
