export function assert(
  condition: unknown,
  message = "assertion failed",
): asserts condition {
  if (!condition) throw new Error(message);
}

export function assertEquals<T>(
  actual: T,
  expected: T,
  message?: string,
): void {
  if (!Object.is(actual, expected)) {
    throw new Error(
      message ?? `expected ${String(expected)}, got ${String(actual)}`,
    );
  }
}

export function assertBytesEqual(
  actual: Uint8Array,
  expected: Uint8Array,
): void {
  assertEquals(actual.byteLength, expected.byteLength, "byte lengths differ");
  for (let index = 0; index < actual.byteLength; index += 1) {
    if (actual[index] !== expected[index]) {
      throw new Error(`bytes differ at offset ${index}`);
    }
  }
}

export async function assertRejects(
  operation: () => unknown | Promise<unknown>,
  check?: (error: unknown) => void,
): Promise<void> {
  try {
    await operation();
  } catch (error) {
    check?.(error);
    return;
  }
  throw new Error("expected operation to reject");
}
