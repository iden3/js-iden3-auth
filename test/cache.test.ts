import { ICache, IN_MEMORY_CACHE } from '../src/cache';

describe('Cache', () => {
  describe('ICache interface', () => {
    let cache: ICache<string>;

    beforeEach(() => {
      cache = IN_MEMORY_CACHE<string>({ ttlMs: 1000 }); // 1 second TTL
    });

    it('should set and get values', async () => {
      await cache.set('key1', 'value1');
      const result = await cache.get('key1');
      expect(result).toBe('value1');
    });

    it('should return undefined for non-existent keys', async () => {
      const result = await cache.get('nonexistent');
      expect(result).toBeUndefined();
    });

    it('should delete values', async () => {
      await cache.set('key1', 'value1');
      await cache.delete('key1');
      const result = await cache.get('key1');
      expect(result).toBeUndefined();
    });

    it('should handle multiple keys', async () => {
      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');
      await cache.set('key3', 'value3');

      expect(await cache.get('key1')).toBe('value1');
      expect(await cache.get('key2')).toBe('value2');
      expect(await cache.get('key3')).toBe('value3');
    });

    it('should overwrite existing values', async () => {
      await cache.set('key1', 'oldValue');
      await cache.set('key1', 'newValue');
      const result = await cache.get('key1');
      expect(result).toBe('newValue');
    });
  });

  describe('Expiration functionality', () => {
    it('should expire entries after TTL', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: 50 }); // 50ms TTL

      await cache.set('key1', 'value1');

      // Should be available immediately
      expect(await cache.get('key1')).toBe('value1');

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 60));

      // Should be expired and return undefined
      expect(await cache.get('key1')).toBeUndefined();
    });

    it('should auto-cleanup expired entries on access', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: 50 }); // 50ms TTL

      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 60));

      // Accessing expired entry should clean it up
      expect(await cache.get('key1')).toBeUndefined();

      // Other expired entries should also be cleaned up when accessed
      expect(await cache.get('key2')).toBeUndefined();
    });

    it('should handle different expiration times for different entries', async () => {
      const cache1 = IN_MEMORY_CACHE<string>({ ttlMs: 50 }); // 50ms TTL
      const cache2 = IN_MEMORY_CACHE<string>({ ttlMs: 100 }); // 100ms TTL

      await cache1.set('shortLived', 'value1');
      await cache2.set('longLived', 'value2');

      // After 60ms, short-lived should expire, long-lived should remain
      await new Promise((resolve) => setTimeout(resolve, 60));

      expect(await cache1.get('shortLived')).toBeUndefined();
      expect(await cache2.get('longLived')).toBe('value2');

      // After another 50ms, long-lived should also expire
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(await cache2.get('longLived')).toBeUndefined();
    });

    it('should reset expiration when updating existing key', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: 100 }); // 100ms TTL

      await cache.set('key1', 'value1');

      // Wait 50ms (half the TTL)
      await new Promise((resolve) => setTimeout(resolve, 50));

      // Update the value, which should reset the expiration
      await cache.set('key1', 'updatedValue');

      // Wait another 60ms (total 110ms from first set, but only 60ms from update)
      await new Promise((resolve) => setTimeout(resolve, 60));

      // Should still be available since expiration was reset
      expect(await cache.get('key1')).toBe('updatedValue');

      // Wait another 50ms (now 110ms from update)
      await new Promise((resolve) => setTimeout(resolve, 50));

      // Should now be expired
      expect(await cache.get('key1')).toBeUndefined();
    });
  });

  describe('Permanent storage (no TTL)', () => {
    let permanentCache: ICache<string>;

    beforeEach(() => {
      permanentCache = IN_MEMORY_CACHE<string>({}); // No TTL
    });

    it('should store values permanently when no TTL is set', async () => {
      await permanentCache.set('permanent', 'value');

      // Wait longer than typical TTL would be
      await new Promise((resolve) => setTimeout(resolve, 200));

      // Should still be available
      expect(await permanentCache.get('permanent')).toBe('value');
    });

    it('should handle explicit undefined TTL', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: undefined });

      await cache.set('key1', 'value1');

      // Wait a reasonable time
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Should still be available
      expect(await cache.get('key1')).toBe('value1');
    });

    it('should allow manual deletion of permanent entries', async () => {
      await permanentCache.set('key1', 'value1');
      await permanentCache.delete('key1');

      expect(await permanentCache.get('key1')).toBeUndefined();
    });
  });

  describe('Complex data types', () => {
    interface TestObject {
      id: number;
      name: string;
      nested: { prop: boolean };
    }

    it('should handle object types', async () => {
      const cache = IN_MEMORY_CACHE<TestObject>({ ttlMs: 1000 });

      const testObj: TestObject = {
        id: 1,
        name: 'test',
        nested: { prop: true }
      };

      await cache.set('object', testObj);
      const result = await cache.get('object');

      expect(result).toEqual(testObj);
      expect(result?.nested.prop).toBe(true);
    });

    it('should handle array types', async () => {
      const cache = IN_MEMORY_CACHE<number[]>({ ttlMs: 1000 });

      const testArray = [1, 2, 3, 4, 5];

      await cache.set('array', testArray);
      const result = await cache.get('array');

      expect(result).toEqual(testArray);
      expect(result?.length).toBe(5);
    });

    it('should handle null and undefined values', async () => {
      const cache = IN_MEMORY_CACHE<string | null>({ ttlMs: 1000 });

      await cache.set('nullValue', null);
      const result = await cache.get('nullValue');

      expect(result).toBeNull();
    });
  });

  describe('Edge cases', () => {
    it('should handle very short TTL', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: 1 }); // 1ms TTL

      await cache.set('shortLived', 'value');

      // Wait just a bit
      await new Promise((resolve) => setTimeout(resolve, 5));

      expect(await cache.get('shortLived')).toBeUndefined();
    });

    it('should handle zero TTL', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: 0 });

      await cache.set('zeroTTL', 'value');

      // Should expire immediately
      expect(await cache.get('zeroTTL')).toBeUndefined();
    });

    it('should handle negative TTL', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: -100 });

      await cache.set('negativeTTL', 'value');

      // Should expire immediately
      expect(await cache.get('negativeTTL')).toBeUndefined();
    });

    it('should handle deleting non-existent keys gracefully', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: 1000 });

      // Should not throw error
      await expect(cache.delete('nonexistent')).resolves.toBeUndefined();
    });

    it('should handle concurrent operations', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: 1000 });

      // Set multiple values concurrently
      const setPromises = Array.from({ length: 10 }, (_, i) => cache.set(`key${i}`, `value${i}`));

      await Promise.all(setPromises);

      // Get all values concurrently
      const getPromises = Array.from({ length: 10 }, (_, i) => cache.get(`key${i}`));

      const results = await Promise.all(getPromises);

      // All values should be retrieved correctly
      results.forEach((result, i) => {
        expect(result).toBe(`value${i}`);
      });
    });

    it('should handle large number of entries', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: 5000 });

      // Set 1000 entries
      for (let i = 0; i < 1000; i++) {
        await cache.set(`key${i}`, `value${i}`);
      }

      // Verify a few random entries
      expect(await cache.get('key0')).toBe('value0');
      expect(await cache.get('key500')).toBe('value500');
      expect(await cache.get('key999')).toBe('value999');
    });
  });

  describe('Memory management', () => {
    it('should clean up expired entries to prevent memory leaks', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: 50 });

      // Add many entries
      for (let i = 0; i < 100; i++) {
        await cache.set(`key${i}`, `value${i}`);
      }

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 60));

      // Access some entries to trigger cleanup
      for (let i = 0; i < 10; i++) {
        expect(await cache.get(`key${i}`)).toBeUndefined();
      }

      // All accessed entries should be cleaned up (undefined)
      for (let i = 0; i < 10; i++) {
        expect(await cache.get(`key${i}`)).toBeUndefined();
      }
    });
  });

  describe('Auto cleanup functionality', () => {
    it('should automatically clean up expired entries with autoCleanupMs', async () => {
      const cache = IN_MEMORY_CACHE<string>({
        ttlMs: 50, // 50ms TTL
        autoCleanupMs: 30 // cleanup every 30ms
      });

      // Add entries
      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');
      await cache.set('key3', 'value3');

      // Initially all should be present
      expect(await cache.size()).toBe(3);

      // Wait for entries to expire and auto cleanup to run
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Auto cleanup should have removed expired entries
      expect(await cache.size()).toBe(0);

      // Stop cleanup to prevent interference with other tests
      cache.stopCleanup();
    });

    it('should not cleanup non-expired entries during auto cleanup', async () => {
      const cache = IN_MEMORY_CACHE<string>({
        ttlMs: 200, // 200ms TTL
        autoCleanupMs: 50 // cleanup every 50ms
      });

      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');

      // Wait for one cleanup cycle but not expiration
      await new Promise((resolve) => setTimeout(resolve, 70));

      // Entries should still be there
      expect(await cache.get('key1')).toBe('value1');
      expect(await cache.get('key2')).toBe('value2');
      expect(await cache.size()).toBe(2);

      await cache.stopCleanup();
    });

    it('should handle mixed expired and non-expired entries during auto cleanup', async () => {
      const cache = IN_MEMORY_CACHE<string>({
        ttlMs: 80, // 80ms TTL
        autoCleanupMs: 40 // cleanup every 40ms
      });

      // Add initial entries
      await cache.set('shortLived1', 'value1');
      await cache.set('shortLived2', 'value2');

      // Wait for first set to expire
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Add new entries after first ones have expired
      await cache.set('newEntry1', 'value3');
      await cache.set('newEntry2', 'value4');

      // Wait for cleanup to run
      await new Promise((resolve) => setTimeout(resolve, 50));

      // Old entries should be gone, new ones should remain
      expect(await cache.get('shortLived1')).toBeUndefined();
      expect(await cache.get('shortLived2')).toBeUndefined();
      expect(await cache.get('newEntry1')).toBe('value3');
      expect(await cache.get('newEntry2')).toBe('value4');

      await cache.stopCleanup();
    });

    it('should manually start and stop cleanup', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: 50 });

      // Add entries
      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');

      // Start manual cleanup
      cache.startCleanup(30);

      // Wait for expiration and cleanup
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Should be cleaned up
      expect(await cache.size()).toBe(0);

      // Add new entries
      await cache.set('key3', 'value3');
      await cache.set('key4', 'value4');

      // Stop cleanup
      await cache.stopCleanup();

      // Wait for what would be cleanup time
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Entries should still be there (cleanup stopped)
      // Note: they're expired but cleanup isn't running
      expect(await cache.size()).toBe(2);
    });

    it('should handle invalidate method manually', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: 50 });

      // Add entries
      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');
      await cache.set('key3', 'value3');

      expect(await cache.size()).toBe(3);

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 60));

      // Manual invalidation should clean up expired entries
      await cache.invalidate();

      expect(await cache.size()).toBe(0);
    });

    it('should not affect valid entries when calling invalidate', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: 200 });

      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');

      // Invalidate before expiration
      await cache.invalidate();

      // Valid entries should remain
      expect(await cache.get('key1')).toBe('value1');
      expect(await cache.get('key2')).toBe('value2');
      expect(await cache.size()).toBe(2);
    });

    it('should handle startCleanup with zero or negative interval', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: 50 });

      await cache.set('key1', 'value1');

      // Should not start cleanup with invalid intervals
      cache.startCleanup(0);
      cache.startCleanup(-10);

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 60));

      // No auto cleanup should have occurred
      expect(await cache.size()).toBe(1); // expired entry still there

      cache.stopCleanup(); // ensure cleanup is stopped
    });

    it('should handle deleteAll method', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: 1000 });

      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');
      await cache.set('key3', 'value3');

      expect(await cache.size()).toBe(3);

      // Delete all entries
      await cache.deleteAll();

      expect(await cache.size()).toBe(0);
      expect(await cache.get('key1')).toBeUndefined();
      expect(await cache.get('key2')).toBeUndefined();
      expect(await cache.get('key3')).toBeUndefined();
    });

    it('should handle multiple start/stop cleanup cycles', async () => {
      const cache = IN_MEMORY_CACHE<string>({ ttlMs: 60 });

      // First cycle
      await cache.set('batch1_key1', 'value1');
      await cache.startCleanup(40);

      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(await cache.size()).toBe(0);
      console.log('first cycle');
      await cache.stopCleanup();

      // Second cycle
      await cache.set('batch2_key1', 'value2');
      await cache.set('batch2_key2', 'value3');

      await cache.startCleanup(40);
      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(await cache.size()).toBe(0);
      console.log('second cycle');
      await cache.stopCleanup();
    });

    it('should prevent memory leaks with periodic auto cleanup', async () => {
      const cache = IN_MEMORY_CACHE<string>({
        ttlMs: 30,
        autoCleanupMs: 20
      });

      // Continuously add entries that expire
      for (let batch = 0; batch < 5; batch++) {
        for (let i = 0; i < 20; i++) {
          await cache.set(`batch${batch}_key${i}`, `value${i}`);
        }

        // Wait for expiration and cleanup
        await new Promise((resolve) => setTimeout(resolve, 50));
      }

      // Final check - cache should be empty or nearly empty due to auto cleanup
      const finalSize = await cache.size();
      expect(finalSize).toBeLessThanOrEqual(20); // Allow for some recently added entries

      await cache.stopCleanup();
    });

    afterEach(() => {
      // Ensure cleanup is stopped after each test to prevent interference
      jest.clearAllTimers();
    });
  });
});
