declare module "node:test" {
  export function describe(
    name: string,
    fn: () => void | Promise<void>,
  ): void;
  export function it(name: string, fn: () => void | Promise<void>): void;
}

declare module "node:assert/strict" {
  export function equal<T>(actual: T, expected: T, message?: string): void;
  export function notEqual<T>(actual: T, expected: T, message?: string): void;
  export function deepEqual<T>(actual: T, expected: T, message?: string): void;
  export function ok(value: unknown, message?: string): asserts value;
  export function throws(
    block: () => unknown,
    error?: RegExp | (new (...args: never[]) => Error) | ((err: unknown) => boolean),
    message?: string,
  ): void;
}
