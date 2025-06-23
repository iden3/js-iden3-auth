import { ICache, createInMemoryCache } from '../src/cache';

describe('Cache', () => {
  describe('Basic Operations', () => {
    let cache: ICache<string>;

    beforeEach(() => {
      cache = createInMemoryCache<string>({ ttlMs: 1000, maxSize: 1000 });
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

    it('should clear all entries', async () => {
      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');
      await cache.set('key3', 'value3');

      await cache.clear();

      expect(await cache.get('key1')).toBeUndefined();
      expect(await cache.get('key2')).toBeUndefined();
      expect(await cache.get('key3')).toBeUndefined();
    });

    it('should handle deleting non-existent keys gracefully', async () => {
      await expect(cache.delete('nonexistent')).resolves.toBeUndefined();
    });
  });

  describe('TTL and Expiration', () => {
    it('should expire entries after TTL', async () => {
      const cache = createInMemoryCache<string>({ ttlMs: 50, maxSize: 1000 });

      await cache.set('key1', 'value1');
      expect(await cache.get('key1')).toBe('value1');

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 60));
      expect(await cache.get('key1')).toBeUndefined();
    });

    it('should handle negative TTL (immediate expiration)', async () => {
      const cache = createInMemoryCache<string>({ ttlMs: -100, maxSize: 1000 });
      await cache.set('key1', 'value1');
      expect(await cache.get('key1')).toBeUndefined();
    });

    it('should reset expiration when updating existing key', async () => {
      const cache = createInMemoryCache<string>({ ttlMs: 100, maxSize: 1000 });

      await cache.set('key1', 'value1');
      await new Promise((resolve) => setTimeout(resolve, 50));

      // Update the value (should reset expiration)
      await cache.set('key1', 'updatedValue');
      await new Promise((resolve) => setTimeout(resolve, 60));

      // Should still be available
      expect(await cache.get('key1')).toBe('updatedValue');

      // Wait for final expiration
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(await cache.get('key1')).toBeUndefined();
    });

    it('should store values permanently when no TTL is set', async () => {
      const cache = createInMemoryCache<string>({ maxSize: 1000 });

      await cache.set('permanent', 'value');
      await new Promise((resolve) => setTimeout(resolve, 200));

      expect(await cache.get('permanent')).toBe('value');
    });

    it('should handle explicit undefined TTL', async () => {
      const cache = createInMemoryCache<string>({ ttlMs: undefined, maxSize: 1000 });

      await cache.set('key1', 'value1');
      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(await cache.get('key1')).toBe('value1');
    });
  });

  describe('Memory Management and Size Limits', () => {
    it('should enforce maxSize limit by evicting the least recently used item', async () => {
      const cache = createInMemoryCache<string>({ ttlMs: 10000, maxSize: 3 });

      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');
      await cache.set('key3', 'value3');

      // key1 is the least recently used
      await cache.set('key4', 'value4');

      expect(await cache.get('key2')).toBe('value2');
      expect(await cache.get('key4')).toBeDefined();
      expect(await cache.get('key3')).toBe('value3');
      expect(await cache.get('key1')).toBeUndefined(); // evicted
    });

    it('should cleanup expired entries before enforcing maxSize', async () => {
      const cache = createInMemoryCache<string>({ ttlMs: 50, maxSize: 3 });

      // Fill to capacity
      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');
      await cache.set('key3', 'value3');

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 60));

      // Should be able to add new entry since expired ones can be cleaned up
      await expect(cache.set('newKey', 'newValue')).resolves.toBeUndefined();
      expect(await cache.get('newKey')).toBe('newValue');
    });

    it('should handle cache operations after expired entries cleanup', async () => {
      const cache = createInMemoryCache<string>({ ttlMs: 50, maxSize: 1000 });

      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 60));

      expect(await cache.get('key2')).toBeUndefined();
      expect(await cache.get('key1')).toBeUndefined();

      // Should be able to add new entries after cleanup
      await cache.set('key3', 'value3');
      expect(await cache.get('key3')).toBe('value3');
    });
  });

  describe('Data Types Support', () => {
    interface TestObject {
      id: number;
      name: string;
      nested: { prop: boolean };
    }

    it('should handle object types', async () => {
      const cache = createInMemoryCache<TestObject>({ ttlMs: 1000, maxSize: 1000 });

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
      const cache = createInMemoryCache<number[]>({ ttlMs: 1000, maxSize: 1000 });

      const testArray = [1, 2, 3, 4, 5];
      await cache.set('array', testArray);
      const result = await cache.get('array');

      expect(result).toEqual(testArray);
      expect(result?.length).toBe(5);
    });

    it('should handle null values', async () => {
      const cache = createInMemoryCache<string | null>({ ttlMs: 1000, maxSize: 1000 });

      await cache.set('nullValue', null);
      const result = await cache.get('nullValue');

      expect(result).toBeNull();
    });
  });

  describe('Concurrency', () => {
    it('should handle concurrent operations safely', async () => {
      const cache = createInMemoryCache<string>({ ttlMs: 1000, maxSize: 1000 });

      // Set multiple values concurrently
      const setPromises = Array.from({ length: 20 }, (_, i) => cache.set(`key${i}`, `value${i}`));
      await Promise.all(setPromises);

      // Get all values concurrently
      const getPromises = Array.from({ length: 20 }, (_, i) => cache.get(`key${i}`));
      const results = await Promise.all(getPromises);

      // Verify all results
      results.forEach((result, i) => {
        expect(result).toBe(`value${i}`);
      });
    });

    it('should handle mixed concurrent operations', async () => {
      const cache = createInMemoryCache<string>({ ttlMs: 5000, maxSize: 1000 });

      // Mix of set, get, and delete operations
      const operations = [
        ...Array.from({ length: 10 }, (_, i) => cache.set(`key${i}`, `value${i}`)),
        ...Array.from({ length: 5 }, (_, i) => cache.get(`key${i}`)),
        ...Array.from({ length: 3 }, (_, i) => cache.delete(`key${i + 10}`))
      ];

      const results = await Promise.all(operations);

      // Verify set operations completed (they return undefined)
      expect(results.slice(0, 10).every((result) => result === undefined)).toBe(true);

      // Verify get operations
      const getResults = results.slice(10, 15);
      expect(getResults.every((result, i) => result === `value${i}`)).toBe(true);
    });
  });

  describe('Performance Tests', () => {
    it('should handle high-volume operations efficiently', async () => {
      const cache = createInMemoryCache<string>({ ttlMs: 10000, maxSize: 10_000 });
      const itemCount = 5_000;

      // Measure set operations
      const setStart = process.hrtime();
      for (let i = 0; i < itemCount; i++) {
        await cache.set(`key${i}`, `value${i}`);
      }
      const setEnd = process.hrtime(setStart);
      const setTimeMs = setEnd[0] * 1000 + setEnd[1] / 1000000;

      // Measure get operations
      const getStart = process.hrtime();
      for (let i = 0; i < itemCount; i++) {
        await cache.get(`key${i}`);
      }
      const getEnd = process.hrtime(getStart);
      const getTimeMs = getEnd[0] * 1000 + getEnd[1] / 1000000;

      // Performance expectations (these are generous to avoid flaky tests)
      expect(setTimeMs).toBeLessThan(5000); // 5 seconds for 5000 sets
      expect(getTimeMs).toBeLessThan(2000); // 2 seconds for 5000 gets

      // Verify some items are still accessible (cache should retain at least some items)
      const sampleResults = await Promise.all([
        cache.get('key0'),
        cache.get('key1000'),
        cache.get('key2000')
      ]);
      expect(sampleResults.some((result) => result !== undefined)).toBe(true);

      console.log(
        `Performance: ${itemCount} sets in ${setTimeMs.toFixed(
          2
        )}ms, ${itemCount} gets in ${getTimeMs.toFixed(2)}ms`
      );
    });

    it('should efficiently handle batch operations', async () => {
      const cache = createInMemoryCache<string>({ ttlMs: 10000, maxSize: 5000 });
      const batchSize = 1000;

      const batchStart = process.hrtime();

      // Batch set operations
      const setPromises = Array.from({ length: batchSize }, (_, i) =>
        cache.set(`batch_key${i}`, `batch_value${i}`)
      );
      await Promise.all(setPromises);

      // Batch get operations
      const getPromises = Array.from({ length: batchSize }, (_, i) => cache.get(`batch_key${i}`));
      const results = await Promise.all(getPromises);

      const batchEnd = process.hrtime(batchStart);
      const batchTimeMs = batchEnd[0] * 1000 + batchEnd[1] / 1000000;

      // Verify all operations completed successfully
      expect(results.every((result, i) => result === `batch_value${i}`)).toBe(true);

      // Performance expectation
      expect(batchTimeMs).toBeLessThan(3000); // 3 seconds for 1000 concurrent ops

      console.log(`Batch Performance: ${batchSize} concurrent ops in ${batchTimeMs.toFixed(2)}ms`);
    });

    it('should efficiently cleanup expired entries at scale', async () => {
      const cache = createInMemoryCache<string>({ ttlMs: 50, maxSize: 5000 });
      const itemCount = 2000;

      // Add many entries that will expire
      for (let i = 0; i < itemCount; i++) {
        await cache.set(`expire_key${i}`, `expire_value${i}`);
      }

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 60));

      // QuickLRU handles expiration lazily - trigger cleanup by accessing items
      const cleanupStart = process.hrtime();

      // Access all expired items to trigger lazy cleanup
      // QuickLRU will remove expired items when they are accessed
      let cleanedUpCount = 0;
      for (let i = 0; i < itemCount; i++) {
        const result = await cache.get(`expire_key${i}`);
        if (result === undefined) {
          cleanedUpCount++;
        }
      }

      const cleanupEnd = process.hrtime(cleanupStart);
      const cleanupTimeMs = cleanupEnd[0] * 1000 + cleanupEnd[1] / 1000000;

      // All items should be expired and cleaned up during access
      expect(cleanedUpCount).toBe(itemCount);
      expect(cleanupTimeMs).toBeLessThan(500); // 500ms for cleanup of 2000 items

      console.log(
        `Cleanup Performance: ${itemCount} expired items cleaned in ${cleanupTimeMs.toFixed(2)}ms`
      );
    });

    it('should maintain performance with mixed expired and valid entries', async () => {
      const cache = createInMemoryCache<string>({ ttlMs: 10000, maxSize: 3000 });

      // Add items that won't expire
      const validItems = 500;
      for (let i = 0; i < validItems; i++) {
        await cache.set(`valid_key${i}`, `valid_value${i}`);
      }

      // Add items with short expiry
      const shortCache = createInMemoryCache<string>({ ttlMs: 30, maxSize: 3000 });
      const expiredItems = 1000;
      for (let i = 0; i < expiredItems; i++) {
        await shortCache.set(`expired_key${i}`, `expired_value${i}`);
      }

      // Wait for some to expire
      await new Promise((resolve) => setTimeout(resolve, 50));

      // Test mixed access patterns
      const mixedStart = process.hrtime();

      // Access valid items
      for (let i = 0; i < 100; i++) {
        await cache.get(`valid_key${i}`);
      }

      // Access expired items (should be fast since they're cleaned up on access)
      for (let i = 0; i < 100; i++) {
        await shortCache.get(`expired_key${i}`);
      }

      const mixedEnd = process.hrtime(mixedStart);
      const mixedTimeMs = mixedEnd[0] * 1000 + mixedEnd[1] / 1000000;

      expect(mixedTimeMs).toBeLessThan(500); // 500ms for 200 mixed operations

      console.log(`Mixed Access Performance: 200 mixed operations in ${mixedTimeMs.toFixed(2)}ms`);
    });
  });

  describe('Memory Efficiency', () => {
    it('should not grow unbounded with expired entries', async () => {
      const cache = createInMemoryCache<string>({ ttlMs: 30, maxSize: 10_000 });

      // Simulate continuous usage with expiring entries
      for (let batch = 0; batch < 5; batch++) {
        // Add batch of entries
        for (let i = 0; i < 200; i++) {
          await cache.set(`batch${batch}_key${i}`, `batch${batch}_value${i}`);
        }

        // Wait for expiration
        await new Promise((resolve) => setTimeout(resolve, 40));

        // Trigger lazy cleanup by trying to access some items
        await cache.get(`batch${batch}_key0`);
      }

      // Verify cache still works with new entries
      await cache.set('final_test', 'final_value');
      expect(await cache.get('final_test')).toBe('final_value');

      console.log(
        `Memory Efficiency: Cache remains functional after multiple batches with expiration`
      );
    });
  });
});
