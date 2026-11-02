/**
 * `application/vnd.amazon.eventstream` decoder.
 *
 * Wire format (all integers big-endian):
 *
 *   [total length     u32]
 *   [headers length   u32]
 *   [prelude CRC32    u32]   <- CRC over the first 8 bytes
 *   [headers          headers_length]
 *   [payload          total_length - headers_length - 16]
 *   [message CRC32    u32]   <- CRC over the entire message minus the trailing 4 bytes
 *
 * Headers: a sequence of `[name_len u8][name utf8][value_type u8][value …]`.
 * We only need the typed values Bedrock emits (boolean true/false, byte, short,
 * integer, long, byte-array, string, timestamp, uuid). All are surfaced as
 * strings for ease of consumption — Bedrock only sets string-valued headers in
 * practice (`:event-type`, `:message-type`, `:content-type`, `:exception-type`).
 */

import * as AIError from "../error";

const PRELUDE_LEN = 8;
const PRELUDE_CRC_LEN = 4;
const MESSAGE_CRC_LEN = 4;
const HEADER_BLOCK_OFFSET = PRELUDE_LEN + PRELUDE_CRC_LEN;
const MIN_MESSAGE_LEN = HEADER_BLOCK_OFFSET + MESSAGE_CRC_LEN;
/** Current service-side message limit from aws-c-event-stream. */
export const MAX_MESSAGE_LEN = 24 * 1024 * 1024;
/** Wire-level encoded-header limit from the Amazon Event Stream specification. */
export const MAX_HEADERS_LEN = 128 * 1024;
/** Shared across messages: every header decode is a complete, non-streaming call. */
const HEADER_DECODER = new TextDecoder("utf-8", { fatal: true });

export interface EventStreamMessage {
	/** Lower-cased copy is *not* applied — Bedrock uses casing like `:event-type` verbatim. */
	headers: Record<string, string>;
	payload: Uint8Array;
}

/** CRC32 (IEEE / zlib polynomial 0xEDB88320), matches `@aws-crypto/crc32`. */
export function crc32(bytes: Uint8Array): number {
	return Bun.hash.crc32(bytes) >>> 0;
}

/**
 * Validate a 12-byte prelude (lengths and prelude CRC) and return the total
 * message length. Mirrors smithy-rs: the header block must fit between the
 * prelude and the message CRC. Runs before any message bytes are buffered.
 */
function declaredMessageLength(prelude: Uint8Array): number {
	const view = new DataView(prelude.buffer, prelude.byteOffset, HEADER_BLOCK_OFFSET);
	if (crc32(prelude.subarray(0, PRELUDE_LEN)) !== view.getUint32(PRELUDE_LEN, false))
		throw new AIError.EventStreamFrameError("prelude CRC mismatch");
	const total = view.getUint32(0, false);
	if (total < MIN_MESSAGE_LEN) throw new AIError.EventStreamFrameError(`total length ${total} below minimum`);
	if (total > MAX_MESSAGE_LEN)
		throw new AIError.EventStreamFrameError(`total length ${total} exceeds maximum ${MAX_MESSAGE_LEN}`);
	const headersLen = view.getUint32(4, false);
	if (headersLen > MAX_HEADERS_LEN)
		throw new AIError.EventStreamFrameError(`headers length ${headersLen} exceeds maximum ${MAX_HEADERS_LEN}`);
	if (headersLen > total - MIN_MESSAGE_LEN)
		throw new AIError.EventStreamFrameError(`headers length ${headersLen} exceeds message length ${total}`);
	return total;
}

/**
 * Decode a single, fully buffered eventstream message. Throws if the framing is
 * malformed or either CRC mismatches. Used by both `decodeEventStream` (the
 * streaming entry point) and the unit tests, which exercise it with hand-built
 * frames.
 */
export function decodeMessage(frame: Uint8Array): EventStreamMessage {
	if (frame.length < MIN_MESSAGE_LEN) throw new AIError.EventStreamFrameError("frame too short");
	const total = declaredMessageLength(frame);
	if (total !== frame.length)
		throw new AIError.EventStreamFrameError(`framed length ${total} != buffer ${frame.length}`);
	const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
	const headersLen = view.getUint32(4, false);
	const msgCrc = view.getUint32(total - MESSAGE_CRC_LEN, false);
	const computedMsgCrc = crc32(frame.subarray(0, total - MESSAGE_CRC_LEN));
	if (computedMsgCrc !== msgCrc) throw new AIError.EventStreamFrameError("message CRC mismatch");

	const headersBytes = frame.subarray(HEADER_BLOCK_OFFSET, HEADER_BLOCK_OFFSET + headersLen);
	const payload = frame.subarray(HEADER_BLOCK_OFFSET + headersLen, total - MESSAGE_CRC_LEN);
	return { headers: parseHeaders(headersBytes), payload };
}

function requireHeaderBytes(buf: Uint8Array, offset: number, length: number, field: string): void {
	if (length < 0 || offset > buf.length - length) {
		throw new AIError.EventStreamFrameError(`truncated EventStream header ${field}`);
	}
}

function decodeHeaderText(bytes: Uint8Array, field: string): string {
	try {
		return HEADER_DECODER.decode(bytes);
	} catch {
		throw new AIError.EventStreamFrameError(`invalid UTF-8 in EventStream header ${field}`);
	}
}

function parseHeaders(buf: Uint8Array): Record<string, string> {
	const out = Object.create(null) as Record<string, string>;
	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	let p = 0;
	while (p < buf.length) {
		requireHeaderBytes(buf, p, 1, "name length");
		const nameLen = view.getUint8(p++);
		if (nameLen === 0) throw new AIError.EventStreamFrameError("EventStream header name is empty");
		requireHeaderBytes(buf, p, nameLen + 1, "name or type");
		const name = decodeHeaderText(buf.subarray(p, p + nameLen), "name");
		p += nameLen;
		if (Object.hasOwn(out, name)) throw new AIError.EventStreamFrameError(`duplicate EventStream header ${name}`);
		const type = view.getUint8(p++);
		switch (type) {
			case 0:
				out[name] = "true";
				break;
			case 1:
				out[name] = "false";
				break;
			case 2:
				requireHeaderBytes(buf, p, 1, "byte value");
				out[name] = String(view.getInt8(p));
				p += 1;
				break;
			case 3:
				requireHeaderBytes(buf, p, 2, "short value");
				out[name] = String(view.getInt16(p, false));
				p += 2;
				break;
			case 4:
				requireHeaderBytes(buf, p, 4, "integer value");
				out[name] = String(view.getInt32(p, false));
				p += 4;
				break;
			case 5:
				requireHeaderBytes(buf, p, 8, "long value");
				out[name] = bigIntFromBytes(buf.subarray(p, p + 8)).toString();
				p += 8;
				break;
			case 6:
			case 7: {
				requireHeaderBytes(buf, p, 2, "value length");
				const len = view.getUint16(p, false);
				p += 2;
				if (len === 0 || len > 0x7fff) {
					throw new AIError.EventStreamFrameError(`invalid EventStream header value length ${len}`);
				}
				requireHeaderBytes(buf, p, len, type === 6 ? "byte-array value" : "string value");
				out[name] =
					type === 6
						? Buffer.from(buf.buffer, buf.byteOffset + p, len).toString("base64")
						: decodeHeaderText(buf.subarray(p, p + len), "string value");
				p += len;
				break;
			}
			case 8: {
				requireHeaderBytes(buf, p, 8, "timestamp value");
				const date = new Date(Number(bigIntFromBytes(buf.subarray(p, p + 8))));
				if (!Number.isFinite(date.getTime())) throw new AIError.EventStreamFrameError("invalid timestamp header");
				out[name] = date.toISOString();
				p += 8;
				break;
			}
			case 9: {
				requireHeaderBytes(buf, p, 16, "UUID value");
				const hex = Buffer.from(buf.buffer, buf.byteOffset + p, 16).toString("hex");
				out[name] =
					`${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
				p += 16;
				break;
			}
			default:
				throw new AIError.EventStreamFrameError(`unknown header value type ${type}`);
		}
	}
	return out;
}

function bigIntFromBytes(b: Uint8Array): bigint {
	let v = 0n;
	for (let i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]);
	// sign-extend (two's complement)
	if (b.length === 8 && b[0] & 0x80) v -= 1n << 64n;
	return v;
}

/**
 * Async generator that consumes a `ReadableStream<Uint8Array>` (e.g. a fetch
 * response body) and yields fully-framed messages. Handles arbitrary chunk
 * boundaries: messages may span multiple chunks, and a single chunk may carry
 * many messages.
 *
 * A message wholly inside a chunk is decoded in place. A message that spans
 * chunks is copied once into a buffer of its declared (bounded) length, so
 * memory never exceeds one message plus the current chunk, and payloads
 * already yielded are never overwritten.
 */
export async function* decodeEventStream(source: ReadableStream<Uint8Array>): AsyncGenerator<EventStreamMessage> {
	const reader = source.getReader();
	// The 12-byte prelude of a message split across chunks.
	const prelude = new Uint8Array(HEADER_BLOCK_OFFSET);
	let preludeFilled = 0;
	// A message split across chunks, sized from its validated prelude.
	let pending: Uint8Array | undefined;
	let pendingFilled = 0;
	let completed = false;
	try {
		while (true) {
			const { value: chunk, done } = await reader.read();
			if (done) break;
			let offset = 0;
			while (offset < chunk.length) {
				if (pending) {
					const count = Math.min(pending.length - pendingFilled, chunk.length - offset);
					pending.set(chunk.subarray(offset, offset + count), pendingFilled);
					pendingFilled += count;
					offset += count;
					if (pendingFilled < pending.length) break;
					const frame = pending;
					pending = undefined;
					yield decodeMessage(frame);
					continue;
				}
				if (preludeFilled > 0 || chunk.length - offset < HEADER_BLOCK_OFFSET) {
					const count = Math.min(HEADER_BLOCK_OFFSET - preludeFilled, chunk.length - offset);
					prelude.set(chunk.subarray(offset, offset + count), preludeFilled);
					preludeFilled += count;
					offset += count;
					if (preludeFilled < HEADER_BLOCK_OFFSET) break;
					preludeFilled = 0;
					pending = new Uint8Array(declaredMessageLength(prelude));
					pending.set(prelude);
					pendingFilled = HEADER_BLOCK_OFFSET;
					continue;
				}
				const total = declaredMessageLength(chunk.subarray(offset, offset + HEADER_BLOCK_OFFSET));
				if (chunk.length - offset >= total) {
					yield decodeMessage(chunk.subarray(offset, offset + total));
					offset += total;
					continue;
				}
				pending = new Uint8Array(total);
				pendingFilled = 0;
			}
		}
		if (pending || preludeFilled > 0) throw new AIError.EventStreamFrameError("truncated message at end of stream");
		completed = true;
	} finally {
		// On abnormal exit (consumer threw/broke, decode error) cancel the body so the
		// HTTP connection is released instead of draining until GC.
		if (!completed) await reader.cancel().catch(() => {});
		reader.releaseLock();
	}
}
