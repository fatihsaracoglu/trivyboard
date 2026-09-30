import { ref, watch, onUnmounted, type Ref } from "vue";

interface UseApiOptions {
  enabled?: () => boolean;
  refetchInterval?: number;
  placeholderData?: unknown;
}

interface UseApiResult<T> {
  data: Ref<T | null>;
  isLoading: Ref<boolean>;
  isError: Ref<boolean>;
  error: Ref<unknown>;
  isFetching: Ref<boolean>;
  refetch: () => Promise<void>;
}

export function useApi<T>(
  fn: () => Promise<T>,
  deps: () => unknown[],
  opts: UseApiOptions = {},
): UseApiResult<T> {
  const data = ref<T | null>(opts.placeholderData as T | null) as Ref<T | null>;
  const isLoading = ref(false);
  const isError = ref(false);
  const error = ref<unknown>(null);
  const isFetching = ref(false);

  let pollTimer: ReturnType<typeof setInterval> | null = null;
  let active = true;

  async function execute() {
    if (opts.enabled && !opts.enabled()) return;
    if (!data.value) isLoading.value = true;
    isFetching.value = true;
    isError.value = false;
    error.value = null;
    try {
      const result = await fn();
      if (active) {
        data.value = result;
      }
    } catch (e) {
      if (active) {
        isError.value = true;
        error.value = e;
      }
    } finally {
      if (active) {
        isLoading.value = false;
        isFetching.value = false;
      }
    }
  }

  // Watch deps and re-fetch when they change.
  watch(
    deps,
    () => execute(),
    { immediate: true },
  );

  // Polling.
  if (opts.refetchInterval && opts.refetchInterval > 0) {
    pollTimer = setInterval(() => execute(), opts.refetchInterval);
  }

  onUnmounted(() => {
    active = false;
    if (pollTimer) clearInterval(pollTimer);
  });

  return {
    data,
    isLoading,
    isError,
    error,
    isFetching,
    refetch: execute,
  };
}

// Mutation helper — wraps an async function with pending/error state.
export function useMutation<TArgs extends unknown[], TResult>(
  fn: (...args: TArgs) => Promise<TResult>,
) {
  const isPending = ref(false);
  const isError = ref(false);
  const error = ref<unknown>(null);
  const data = ref<TResult | null>(null);

  async function mutate(...args: TArgs): Promise<TResult | null> {
    isPending.value = true;
    isError.value = false;
    error.value = null;
    try {
      const result = await fn(...args);
      data.value = result;
      return result;
    } catch (e) {
      isError.value = true;
      error.value = e;
      return null;
    } finally {
      isPending.value = false;
    }
  }

  return { isPending, isError, error, data, mutate };
}
