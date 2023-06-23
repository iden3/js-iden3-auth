import { ISchemaLoader, SchemaLoadResult } from '@lib/loaders';
import { IStateResolver, ResolvedState } from '@lib/state/resolver';

export class MockResolver implements IStateResolver {
  resolve(): Promise<ResolvedState> {
    const t: ResolvedState = {
      latest: true,
      state: null,
      genesis: false,
      transitionTimestamp: 0,
    };
    return Promise.resolve(t);
  }
  rootResolve(): Promise<ResolvedState> {
    const t: ResolvedState = {
      latest: true,
      state: null,
      genesis: false,
      transitionTimestamp: 0,
    };
    return Promise.resolve(t);
  }
}

export class MockJSONLDSchemaLoader implements ISchemaLoader {
  constructor(private readonly schema: string) {}

  async load(): Promise<SchemaLoadResult> {
    const t: SchemaLoadResult = {
      schema: new TextEncoder().encode(this.schema),
      extension: 'json-ld',
    };
    return t;
  }
}
