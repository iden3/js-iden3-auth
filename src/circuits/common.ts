import { Id } from '@iden3/js-iden3-core';
import { IStateResolver, ResolvedState } from '@lib/state/resolver';
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
  if (!gistStateResolved.latest) {
    throw gistStateError;
  }
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
  if (
    !issuerNonRevStateResolved.latest &&
    Date.now() - Number(issuerNonRevStateResolved.transitionTimestamp) * 1000 >
      60 * 60 * 1000
  ) {
    throw new Error(`issuer state for non-revocation proofs is not valid`);
  }
  return issuerNonRevStateResolved;
}
