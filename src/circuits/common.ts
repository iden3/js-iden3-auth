import { Id } from '@lib/core/id';
import { IStateResolver, ResolvedState } from '@lib/state/resolver';

export const userStateError = new Error('user state is not valid');

export async function checkUserState(
  resolver: IStateResolver,
  userId: Id,
  userState: bigint,
): Promise<ResolvedState> {
  const userStateResolved: ResolvedState = await resolver.resolve(
    userId.bigInt(),
    userState,
  );
  if (!userStateResolved.latest) {
    throw userStateError;
  }
  return userStateResolved;
}

export async function checkIssuerNonRevState(
  resolver: IStateResolver,
  issuerId: Id,
  issuerClaimNonRevState: bigint,
): Promise<ResolvedState> {
  const issuerNonRevStateResolved: ResolvedState = await resolver.resolve(
    issuerId.bigInt(),
    issuerClaimNonRevState,
  );
  if (
    !issuerNonRevStateResolved.latest &&
    Date.now() - Number(issuerNonRevStateResolved.transitionTimestamp) * 1000 >
      60 * 60 * 1000 * 24 * 30 * 2 // 2 month
  ) {
    throw new Error(`issuer state for non-revocation proofs is not valid`);
  }
  return issuerNonRevStateResolved;
}
