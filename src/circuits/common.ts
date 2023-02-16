import { Id, DID } from '@iden3/js-iden3-core';
import { IStateResolver, ResolvedState, Resolvers } from '@lib/state/resolver';
import { Hash } from '@iden3/js-merkletree';

export const userStateError = new Error(`user state is not valid`);
export const gistStateError = new Error(`gist state is not valid`);

export async function checkUserState(
  resolver: IStateResolver,
  userId: Id,
  userState: Hash,
): Promise<ResolvedState> {
  const userStateResolved: ResolvedState = await resolver.resolve(
    userId.bigInt(),
    userState.bigInt(),
  );
  if (!userStateResolved.latest) {
    throw userStateError;
  }
  return userStateResolved;
}

export async function checkGlobalState(
  resolver: IStateResolver,
  state: Hash,
): Promise<ResolvedState> {
  const gistStateResolved: ResolvedState = await resolver.rootResolve(
    state.bigInt(),
  );
  return gistStateResolved;
}

export async function checkIssuerNonRevState(
  resolver: IStateResolver,
  issuerId: Id,
  issuerClaimNonRevState: Hash,
): Promise<ResolvedState> {
  const issuerNonRevStateResolved: ResolvedState = await resolver.resolve(
    issuerId.bigInt(),
    issuerClaimNonRevState.bigInt(),
  );
  return issuerNonRevStateResolved;
}

export function getResolverByID(resolvers: Resolvers, id: Id): IStateResolver {
  const userDID = DID.parseFromId(id)
  return getResolverByDID(resolvers, userDID)
}

export function getResolverByDID(resolvers: Resolvers, did: DID): IStateResolver {
  return resolvers[`${did.blockchain}:${did.networkId}`]
}
