package main

import (
	"database/sql"
	"sync"

	_ "modernc.org/sqlite"
)

const unknownServiceName = "<unknown>"

// ServiceMapperMemoryCache provides in-memory caching for service name mappings.
type ServiceMapperMemoryCache struct {
	mx    sync.RWMutex
	cache map[string]string
}

// NewServiceMapperMemoryCache creates a new in-memory cache instance.
func NewServiceMapperMemoryCache() *ServiceMapperMemoryCache {
	return &ServiceMapperMemoryCache{
		cache: make(map[string]string),
	}
}

// Lookup returns the service name for a given address from memory cache, and whether it was found.
func (c *ServiceMapperMemoryCache) Lookup(addr string) (string, bool) {
	c.mx.RLock()
	defer c.mx.RUnlock()
	serviceName, found := c.cache[addr]
	if !found {
		return "", false
	}
	// Convert cached "<unknown>" back to empty string for callers.
	if serviceName == unknownServiceName {
		return "", true
	}
	return serviceName, true
}

// Store stores a service name mapping in memory cache.
func (c *ServiceMapperMemoryCache) Store(addr, serviceName string) {
	c.mx.Lock()
	defer c.mx.Unlock()
	// Store empty strings as "<unknown>" to cache negative lookups.
	if serviceName == "" {
		serviceName = unknownServiceName
	}
	c.cache[addr] = serviceName
}

// Size returns the number of entries in the memory cache.
func (c *ServiceMapperMemoryCache) Size() int {
	c.mx.RLock()
	defer c.mx.RUnlock()
	return len(c.cache)
}

// ServiceMapperPersistentCache provides SQLite-backed persistent caching for service name mappings.
type ServiceMapperPersistentCache struct {
	db *sql.DB
}

// NewServiceMapperPersistentCache creates a new persistent cache instance.
func NewServiceMapperPersistentCache(dbFilePath string) *ServiceMapperPersistentCache {
	cache := &ServiceMapperPersistentCache{}
	cache.init(dbFilePath)
	return cache
}

// init initializes the SQLite database and creates the table if needed.
func (c *ServiceMapperPersistentCache) init(dbFilePath string) {
	// Open SQLite database.
	db, err := sql.Open("sqlite", dbFilePath)
	if err != nil {
		// If we can't open database, continue without persistent cache.
		return
	}

	c.db = db

	// Create table if it doesn't exist.
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS service_cache (
		addr TEXT PRIMARY KEY,
		name TEXT NOT NULL
	);`

	if _, err := c.db.Exec(createTableSQL); err != nil {
		// If we can't create table, close db and continue without persistent cache.
		c.db.Close()
		c.db = nil
		return
	}
}

// Lookup returns the service name for a given address from SQLite, and whether it was found.
func (c *ServiceMapperPersistentCache) Lookup(addr string) (string, bool) {
	if c.db == nil {
		return "", false
	}

	var serviceName string
	err := c.db.QueryRow("SELECT name FROM service_cache WHERE addr = ?", addr).Scan(&serviceName)
	if err != nil {
		// Not found or other error
		return "", false
	}

	// Convert cached "<unknown>" back to empty string for callers.
	if serviceName == unknownServiceName {
		return "", true
	}
	return serviceName, true
}

// Store stores a service name mapping in SQLite.
func (c *ServiceMapperPersistentCache) Store(addr, serviceName string) {
	if c.db == nil {
		return
	}

	// Store empty strings as "<unknown>" to cache negative lookups.
	if serviceName == "" {
		serviceName = unknownServiceName
	}

	// Use INSERT OR REPLACE to handle duplicates.
	_, err := c.db.Exec(
		"INSERT OR REPLACE INTO service_cache (addr, name) VALUES (?, ?)",
		addr, serviceName,
	)
	if err != nil {
		// Ignore SQLite errors to not break the main functionality.
	}
}

// Close closes the SQLite database connection.
func (c *ServiceMapperPersistentCache) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}
