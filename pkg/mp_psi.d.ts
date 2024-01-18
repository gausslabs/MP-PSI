/* tslint:disable */
/* eslint-disable */
/**
* @returns {any}
*/
export function state0_bindgen(): any;
/**
* @param {any} message_a_to_b
* @param {Uint32Array} bit_vector
* @returns {any}
*/
export function state1_bindgen(message_a_to_b: any, bit_vector: Uint32Array): any;
/**
* @param {any} private_output_a_state0
* @param {any} public_output_a_state0
* @param {any} message_b_to_a
* @param {Uint32Array} bit_vector
* @returns {any}
*/
export function state2_bindgen(private_output_a_state0: any, public_output_a_state0: any, message_b_to_a: any, bit_vector: Uint32Array): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly state0_bindgen: () => number;
  readonly state1_bindgen: (a: number, b: number, c: number) => number;
  readonly state2_bindgen: (a: number, b: number, c: number, d: number, e: number) => number;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
