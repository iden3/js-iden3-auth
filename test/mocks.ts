import {
  cacheLoader,
  IStateStorage,
  VerifiableConstants,
  RootInfo,
  StateProof,
  VerifyOpts,
  CircuitData,
  AuthDataPrepareFunc,
  StateVerificationFunc,
  IPackageManager,
  DataPrepareHandlerFunc,
  VerificationHandlerFunc,
  VerificationParams,
  ProvingParams,
  ZKPPacker,
  PackageManager,
  PlainPacker,
  InMemoryPrivateKeyStore,
  BjjProvider,
  KmsKeyType,
  KMS,
  CredentialStorage,
  InMemoryDataSource,
  W3CCredential,
  IdentityStorage,
  Identity,
  Profile,
  InMemoryMerkleTreeStorage
} from '@0xpolygonid/js-sdk';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { proving } from '@iden3/js-jwz';
import { IStateResolver, ResolvedState, Resolvers } from '@lib/state/resolver';
import { DIDResolutionResult } from 'did-resolver';

class MockResolver implements IStateResolver {
  resolve(): Promise<ResolvedState> {
    const t: ResolvedState = {
      latest: true,
      state: null,
      genesis: false,
      transitionTimestamp: 0
    };
    return Promise.resolve(t);
  }
  rootResolve(): Promise<ResolvedState> {
    const t: ResolvedState = {
      latest: true,
      state: null,
      genesis: false,
      transitionTimestamp: 0
    };
    return Promise.resolve(t);
  }
}

export const exampleDidDoc = {
  '@context': [
    'https://www.w3.org/ns/did/v1',
    {
      EcdsaSecp256k1RecoveryMethod2020:
        'https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020',
      blockchainAccountId: 'https://w3id.org/security#blockchainAccountId'
    }
  ],
  id: 'did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65',
  verificationMethod: [
    {
      id: 'did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020',
      type: 'EcdsaSecp256k1RecoveryMethod2020',
      controller: 'did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65',
      blockchainAccountId: 'eip155:137:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65'
    }
  ],
  authentication: ['did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020'],
  assertionMethod: ['did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020']
};

export const testOpts: VerifyOpts = {
  acceptedStateTransitionDelay: 5 * 60 * 1000, // 5 minutes
  acceptedProofGenerationDelay: 10 * 365 * 24 * 60 * 60 * 1000 // 10 years
};

const mockStateResolver: MockResolver = new MockResolver();
export const resolvers: Resolvers = {
  'polygon:mumbai': mockStateResolver
};
export const resolveDIDDocument = {
  resolve: () => Promise.resolve({ didDocument: exampleDidDoc } as DIDResolutionResult)
};

export const schemaLoader: DocumentLoader = cacheLoader({
  ipfsNodeURL: process.env.IPFS_URL ?? 'https://ipfs.io'
});

export const MOCK_STATE_STORAGE: IStateStorage = {
  getLatestStateById: async () => {
    throw new Error(VerifiableConstants.ERRORS.IDENTITY_DOES_NOT_EXIST);
  },
  getStateInfoByIdAndState: async (id: bigint, state: bigint) => {
    const validTestIds = [
      '19898531390599208021876718705689344940605246460654065917270282371355906561',
      '26675680708205250151451142983868154544835349648265874601395279235340702210',
      '27752766823371471408248225708681313764866231655187366071881070918984471042',
      '21803003425107230045260507608510138502859759480520560654156359021447614978',
      '25191641634853875207018381290409317860151551336133597267061715643603096065',
      '22942594156266665426613462771725327314382647426959044863446866613003751938'
    ];
    if (validTestIds.includes(id.toString())) {
      return { id, state };
    }
    throw new Error(VerifiableConstants.ERRORS.IDENTITY_DOES_NOT_EXIST);
  },
  publishState: async () => {
    return '0xc837f95c984892dbcc3ac41812ecb145fedc26d7003202c50e1b87e226a9b33c';
  },
  getGISTProof: (): Promise<StateProof> => {
    return Promise.resolve({
      root: 0n,
      existence: false,
      siblings: [],
      index: 0n,
      value: 0n,
      auxExistence: false,
      auxIndex: 0n,
      auxValue: 0n
    });
  },
  getGISTRootInfo: (): Promise<RootInfo> => {
    return Promise.resolve({
      root: 0n,
      replacedByRoot: 0n,
      createdAtTimestamp: 0n,
      replacedAtTimestamp: 0n,
      createdAtBlock: 0n,
      replacedAtBlock: 0n
    });
  }
};

export const getPackageMgr = async (
  circuitData: CircuitData,
  prepareFn: AuthDataPrepareFunc,
  stateVerificationFn: StateVerificationFunc
): Promise<IPackageManager> => {
  const authInputsHandler = new DataPrepareHandlerFunc(prepareFn);

  const verificationFn = new VerificationHandlerFunc(stateVerificationFn);
  const mapKey = proving.provingMethodGroth16AuthV2Instance.methodAlg.toString();

  if (!circuitData.verificationKey) {
    throw new Error(`verification key doesn't exist for ${circuitData.circuitId}`);
  }
  const verificationParamMap: Map<string, VerificationParams> = new Map([
    [
      mapKey,
      {
        key: circuitData.verificationKey,
        verificationFn
      }
    ]
  ]);

  if (!circuitData.provingKey) {
    throw new Error(`proving doesn't exist for ${circuitData.circuitId}`);
  }
  if (!circuitData.wasm) {
    throw new Error(`wasm file doesn't exist for ${circuitData.circuitId}`);
  }
  const provingParamMap: Map<string, ProvingParams> = new Map();
  provingParamMap.set(mapKey, {
    dataPreparer: authInputsHandler,
    provingKey: circuitData.provingKey,
    wasm: circuitData.wasm
  });

  const mgr: IPackageManager = new PackageManager();
  const packer = new ZKPPacker(provingParamMap, verificationParamMap);
  const plainPacker = new PlainPacker();
  mgr.registerPackers([packer, plainPacker]);

  return mgr;
};

export const registerBJJIntoInMemoryKMS = (): KMS => {
  const memoryKeyStore = new InMemoryPrivateKeyStore();
  const bjjProvider = new BjjProvider(KmsKeyType.BabyJubJub, memoryKeyStore);
  const kms = new KMS();
  kms.registerKeyProvider(KmsKeyType.BabyJubJub, bjjProvider);
  return kms;
};

export const getInMemoryDataStorage = (states: IStateStorage) => {
  return {
    credential: new CredentialStorage(new InMemoryDataSource<W3CCredential>()),
    identity: new IdentityStorage(
      new InMemoryDataSource<Identity>(),
      new InMemoryDataSource<Profile>()
    ),
    mt: new InMemoryMerkleTreeStorage(40),
    states
  };
};
