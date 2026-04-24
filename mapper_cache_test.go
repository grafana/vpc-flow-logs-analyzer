package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServiceMapperMemoryCache(t *testing.T) {
	cache := NewServiceMapperMemoryCache()

	t.Run("empty cache returns not found", func(t *testing.T) {
		serviceName, found := cache.Lookup("1.2.3.4")
		assert.False(t, found)
		assert.Equal(t, "", serviceName)
		assert.Equal(t, 0, cache.Size())
	})

	t.Run("store and lookup known service", func(t *testing.T) {
		cache.Store("1.2.3.4", "web-service")

		serviceName, found := cache.Lookup("1.2.3.4")
		assert.True(t, found)
		assert.Equal(t, "web-service", serviceName)
		assert.Equal(t, 1, cache.Size())
	})

	t.Run("store and lookup empty service name (unknown)", func(t *testing.T) {
		cache.Store("5.6.7.8", "")

		serviceName, found := cache.Lookup("5.6.7.8")
		assert.True(t, found)
		assert.Equal(t, "", serviceName) // Should return empty string to caller
		assert.Equal(t, 2, cache.Size()) // Cache size should increase
	})

	t.Run("overwrite existing entry", func(t *testing.T) {
		cache.Store("1.2.3.4", "updated-service")

		serviceName, found := cache.Lookup("1.2.3.4")
		assert.True(t, found)
		assert.Equal(t, "updated-service", serviceName)
		assert.Equal(t, 2, cache.Size()) // Size shouldn't change
	})

	t.Run("multiple entries", func(t *testing.T) {
		cache.Store("9.10.11.12", "another-service")
		cache.Store("192.168.1.1", "")

		// Check all entries
		serviceName1, found1 := cache.Lookup("1.2.3.4")
		assert.True(t, found1)
		assert.Equal(t, "updated-service", serviceName1)

		serviceName2, found2 := cache.Lookup("5.6.7.8")
		assert.True(t, found2)
		assert.Equal(t, "", serviceName2)

		serviceName3, found3 := cache.Lookup("9.10.11.12")
		assert.True(t, found3)
		assert.Equal(t, "another-service", serviceName3)

		serviceName4, found4 := cache.Lookup("192.168.1.1")
		assert.True(t, found4)
		assert.Equal(t, "", serviceName4)

		assert.Equal(t, 4, cache.Size())
	})
}

func TestServiceMapperPersistentCache(t *testing.T) {
	tempDir := t.TempDir()
	dbFile := filepath.Join(tempDir, "test_cache.db")

	cache := NewServiceMapperPersistentCache(dbFile)
	defer cache.Close()

	t.Run("empty cache returns not found", func(t *testing.T) {
		serviceName, found := cache.Lookup("1.2.3.4")
		assert.False(t, found)
		assert.Equal(t, "", serviceName)
	})

	t.Run("store and lookup known service", func(t *testing.T) {
		cache.Store("1.2.3.4", "web-service")

		serviceName, found := cache.Lookup("1.2.3.4")
		assert.True(t, found)
		assert.Equal(t, "web-service", serviceName)
	})

	t.Run("store and lookup empty service name (unknown)", func(t *testing.T) {
		cache.Store("5.6.7.8", "")

		serviceName, found := cache.Lookup("5.6.7.8")
		assert.True(t, found)
		assert.Equal(t, "", serviceName) // Should return empty string to caller
	})

	t.Run("overwrite existing entry", func(t *testing.T) {
		cache.Store("1.2.3.4", "updated-service")

		serviceName, found := cache.Lookup("1.2.3.4")
		assert.True(t, found)
		assert.Equal(t, "updated-service", serviceName)
	})

	t.Run("persistence across cache instances", func(t *testing.T) {
		// Store some data
		cache.Store("persistent.test", "test-service")
		cache.Store("unknown.test", "")
		cache.Close()

		// Create a new cache instance with the same database
		newCache := NewServiceMapperPersistentCache(dbFile)
		defer newCache.Close()

		// Verify data persisted
		serviceName1, found1 := newCache.Lookup("persistent.test")
		assert.True(t, found1)
		assert.Equal(t, "test-service", serviceName1)

		serviceName2, found2 := newCache.Lookup("unknown.test")
		assert.True(t, found2)
		assert.Equal(t, "", serviceName2)

		// Verify non-existent entry
		serviceName3, found3 := newCache.Lookup("not.stored")
		assert.False(t, found3)
		assert.Equal(t, "", serviceName3)
	})

	t.Run("database failure handling", func(t *testing.T) {
		// Test with invalid database path to ensure graceful handling
		invalidCache := NewServiceMapperPersistentCache("invalid/path/db.db")
		defer invalidCache.Close()

		// Should not crash and should return not found
		serviceName, found := invalidCache.Lookup("test")
		assert.False(t, found)
		assert.Equal(t, "", serviceName)

		// Store should not crash
		invalidCache.Store("test", "value")
	})
}
