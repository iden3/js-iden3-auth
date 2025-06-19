import QuickLRU from 'quick-lru';

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
  const cache = new QuickLRU<string, T>({ maxSize: params.maxSize, maxAge: params.ttlMs });

  return {
    get: async (key: string): Promise<T | undefined> => {
      return cache.get(key);
    },

    set: async (key: string, data: T) => {
      cache.set(key, data);
    },

    deleteAll: async () => {
      cache.clear();
    },

    delete: async (key: string) => {
      cache.delete(key);
    },

    size: async (): Promise<number> => {
      return cache.size;
    }
  };
};
