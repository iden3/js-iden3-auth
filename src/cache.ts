type CacheEntry<T> = {
  data: T;
  expiresAt?: number; // undefined means never expires
};

export interface ICache<T> {
  get(key: string): Promise<T | undefined>;
  set(key: string, data: T): Promise<void>;
  delete(key: string): Promise<void>;
}

export const IN_MEMORY_CACHE = <T>(opts: { ttl?: number }): ICache<T> => {
  const cache = new Map<string, CacheEntry<T>>();
  const isExpired = (entry: CacheEntry<T>): boolean => {
    if (opts.ttl === undefined) {
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
        expiresAt: opts.ttl !== undefined ? Date.now() + opts.ttl : undefined
      };
      cache.set(key, entry);
    },

    delete: async (key: string) => {
      cache.delete(key);
    }
  };
};
