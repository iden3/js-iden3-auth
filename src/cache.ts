type CacheEntry<T> = {
  data: T;
  expiresAt?: number; // undefined means never expires
};

export interface ICache<T> {
  get(key: string): Promise<T | undefined>;
  set(key: string, data: T): Promise<void>;
  delete(key: string): Promise<void>;
  deleteAll(): Promise<void>;
  size(): Promise<number>;
}

export const IN_MEMORY_CACHE = <T>(
  params: { ttlMs?: number; maxSize: number } = { maxSize: 10_000, ttlMs: 5 * 60 * 1000 }
): ICache<T> => {
  const cache = new Map<string, CacheEntry<T>>();

  const isExpired = (entry: CacheEntry<T>): boolean => {
    if (params.ttlMs === undefined || entry.expiresAt === undefined) {
      return false;
    }
    return Date.now() >= entry.expiresAt;
  };

  const cleanupExpired = () => {
    const keysToDelete: string[] = [];
    for (const [key, entry] of cache.entries()) {
      if (isExpired(entry)) {
        keysToDelete.push(key);
      }
    }
    keysToDelete.forEach((key) => cache.delete(key));
    return keysToDelete.length;
  };

  const ensureCapacity = () => {
    // First try to clean up expired entries
    if (cache.size >= params.maxSize) {
      cleanupExpired();
    }

    // If still at capacity after cleanup, throw error
    if (cache.size >= params.maxSize) {
      throw new Error(`Max cache size ${params.maxSize} exceeded`);
    }
  };

  return {
    get: async (key: string): Promise<T | undefined> => {
      const entry = cache.get(key);
      if (!entry) return undefined;

      // Check if this specific entry is expired
      if (isExpired(entry)) {
        cache.delete(key);
        return undefined;
      }

      return entry.data;
    },

    set: async (key: string, data: T) => {
      // Ensure we have capacity before adding
      ensureCapacity();

      const entry: CacheEntry<T> = {
        data,
        expiresAt: params.ttlMs !== undefined ? Date.now() + params.ttlMs : undefined
      };
      cache.set(key, entry);
    },

    deleteAll: async () => {
      cache.clear();
    },

    delete: async (key: string) => {
      cache.delete(key);
    },

    size: async (): Promise<number> => {
      // Clean up expired entries before reporting size
      cleanupExpired();
      return cache.size;
    }
  };
};
