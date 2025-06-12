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
  invalidate(): Promise<void>;
  startCleanup(intervalMs: number): Promise<void>;
  stopCleanup(): Promise<void>;
}

export const IN_MEMORY_CACHE = <T>(opts: { ttlMs?: number; autoCleanupMs?: number }): ICache<T> => {
  const cache = new Map<string, CacheEntry<T>>();
  let cleanupTimer: NodeJS.Timeout | undefined;

  const invalidate = async () => {
    for (const [key, entry] of cache.entries()) {
      if (isExpired(entry)) {
        cache.delete(key);
      }
    }
  };

  const startCleanup = async (intervalMs: number) => {
    if (intervalMs > 0 && !cleanupTimer) {
      cleanupTimer = setInterval(invalidate, intervalMs);
      cleanupTimer.unref?.();
    }
  };

  const stopCleanup = async () => {
    if (cleanupTimer) {
      clearInterval(cleanupTimer);
      cleanupTimer = undefined;
    }
  };

  opts.autoCleanupMs && startCleanup(opts.autoCleanupMs);

  const isExpired = (entry: CacheEntry<T>): boolean => {
    if (opts.ttlMs === undefined) {
      return false;
    }
    return entry.expiresAt !== undefined && Date.now() >= entry.expiresAt;
  };

  return {
    get: async (key: string): Promise<T | undefined> => {
      const entry = cache.get(key);
      if (!entry) return undefined;

      if (isExpired(entry)) {
        cache.delete(key);
        return undefined;
      }

      return entry.data;
    },

    set: async (key: string, data: T) => {
      const entry: CacheEntry<T> = {
        data,
        expiresAt: opts.ttlMs !== undefined ? Date.now() + opts.ttlMs : undefined
      };
      cache.set(key, entry);
    },

    deleteAll: async () => {
      cache.clear();
    },

    delete: async (key: string) => {
      cache.delete(key);
    },

    size: async (): Promise<number> => cache.size,

    invalidate,
    startCleanup,
    stopCleanup
  };
};
