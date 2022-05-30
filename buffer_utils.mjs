import * as utf8 from 'utf8-codec'

export const isU8Arr = input => input instanceof Uint8Array

export function bytelength (input) {
  return typeof input === 'string' ? utf8.encodingLength(input) : input.byteLength
}

export function from (input) {
  if (input instanceof Uint8Array) {
    return input
  }
  if (Array.isArray(input)) {
    return new Uint8Array(input)
  }
  return utf8.encode(input)
}

export function write (arr, str, start) {
  if (typeof str !== 'string') {
    throw new Error('unknown input type')
  }
  utf8.encode(str, arr, start)
  return utf8.encode.bytes
}

export function toHex (buf, start, end) {
  let result = ''
  for (let offset = start; offset < end;) {
    const num = buf[offset++]
    const str = num.toString(16)
    result += (str.length === 1) ? '0' + str : str
  }
  return result
}

const P_24 = Math.pow(2, 24)
const P_16 = Math.pow(2, 16)
const P_8 = Math.pow(2, 8)
export const readUInt32BE = (buf, offset) => buf[offset] * P_24 +
  buf[offset + 1] * P_16 +
  buf[offset + 2] * P_8 +
  buf[offset + 3]

export const readUInt16BE = (buf, offset) => (buf[offset] << 8) | buf[offset + 1]
export const writeUInt32BE = (buf, value, offset) => {
  value = +value
  buf[offset + 3] = value
  value = value >>> 8
  buf[offset + 2] = value
  value = value >>> 8
  buf[offset + 1] = value
  value = value >>> 8
  buf[offset] = value
  return offset + 4
}
export const writeUInt16BE = (buf, value, offset) => {
  buf[offset] = value >> 8
  buf[offset + 1] = value & 0xFF
  return offset + 2
}

export function copy (source, target, targetStart, sourceStart, sourceEnd) {
  if (targetStart < 0) {
    sourceStart -= targetStart
    targetStart = 0
  }

  if (sourceStart < 0) {
    sourceStart = 0
  }

  if (sourceEnd < 0) {
    return new Uint8Array(0)
  }

  if (targetStart >= target.length || sourceStart >= sourceEnd) {
    return 0
  }

  return _copyActual(source, target, targetStart, sourceStart, sourceEnd)
}

function _copyActual (source, target, targetStart, sourceStart, sourceEnd) {
  if (sourceEnd - sourceStart > target.length - targetStart) {
    sourceEnd = sourceStart + target.length - targetStart
  }

  let nb = sourceEnd - sourceStart
  const sourceLen = source.length - sourceStart
  if (nb > sourceLen) {
    nb = sourceLen
  }

  if (sourceStart !== 0 || sourceEnd < source.length) {
    source = new Uint8Array(source.buffer, source.byteOffset + sourceStart, nb)
  }

  target.set(source, targetStart)

  return nb
}
