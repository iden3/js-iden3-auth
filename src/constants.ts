const defaultAuthVerifyOpts = 5 * 60 * 1000; // 5 minutes
const defaultStateTransitionDelay = 1 * 60 * 60 * 1000; // 1 hour;

export const CONSTANTS = {
  ACCEPTED_STATE_TRANSITION_DELAY: defaultStateTransitionDelay,
  CIRCUITS_ARRAY_VALUE_SIZE: 64,
  DEFAULT_CACHE_MAX_SIZE: 10_000,
  STATE_CACHE_OPTIONS: {
    NOT_REPLACED_TTL: defaultStateTransitionDelay / 2,
    REPLACED_TTL: defaultStateTransitionDelay
  },
  GIST_ROOT_CACHE_OPTIONS: {
    NOT_REPLACED_TTL: defaultAuthVerifyOpts / 2, // 2.5 minutes;
    REPLACED_TTL: defaultAuthVerifyOpts // 5 minutes;
  },
  AUTH_ACCEPTED_STATE_TRANSITION_DELAY: defaultAuthVerifyOpts
};
