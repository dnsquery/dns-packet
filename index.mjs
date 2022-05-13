import { Buffer } from 'buffer'
import * as ip from '@leichtgewicht/ip-codec'
import * as types from '@leichtgewicht/dns-packet/types.js'
import * as rcodes from '@leichtgewicht/dns-packet/rcodes.js'
import * as opcodes from '@leichtgewicht/dns-packet/opcodes.js'
import * as classes from '@leichtgewicht/dns-packet/classes.js'
import * as optioncodes from '@leichtgewicht/dns-packet/optioncodes.js'

const QUERY_FLAG = 0
const RESPONSE_FLAG = 1 << 15
const FLUSH_MASK = 1 << 15
const NOT_FLUSH_MASK = ~FLUSH_MASK
const QU_MASK = 1 << 15
const NOT_QU_MASK = ~QU_MASK

function codec ({ bytes = 0, encode, decode, encodingLength }) {
  encode.bytes = bytes
  decode.bytes = bytes
  return {
    encode,
    decode,
    encodingLength: encodingLength || (() => bytes)
  }
}

export const name = codec({
  encode (str, buf, offset) {
    if (!buf) buf = Buffer.alloc(name.encodingLength(str))
    if (!offset) offset = 0
    const oldOffset = offset

    // strip leading and trailing .
    const n = str.replace(/^\.|\.$/gm, '')
    if (n.length) {
      const list = n.split('.')

      for (let i = 0; i < list.length; i++) {
        const len = buf.write(list[i], offset + 1)
        buf[offset] = len
        offset += len + 1
      }
    }

    buf[offset++] = 0

    name.encode.bytes = offset - oldOffset
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0

    const list = []
    let oldOffset = offset
    let totalLength = 0
    let consumedBytes = 0
    let jumped = false

    while (true) {
      if (offset >= buf.length) {
        throw new Error('Cannot decode name (buffer overflow)')
      }
      const len = buf[offset++]
      consumedBytes += jumped ? 0 : 1

      if (len === 0) {
        break
      } else if ((len & 0xc0) === 0) {
        if (offset + len > buf.length) {
          throw new Error('Cannot decode name (buffer overflow)')
        }
        totalLength += len + 1
        if (totalLength > 254) {
          throw new Error('Cannot decode name (name too long)')
        }
        list.push(buf.toString('utf-8', offset, offset + len))
        offset += len
        consumedBytes += jumped ? 0 : len
      } else if ((len & 0xc0) === 0xc0) {
        if (offset + 1 > buf.length) {
          throw new Error('Cannot decode name (buffer overflow)')
        }
        const jumpOffset = buf.readUInt16BE(offset - 1) - 0xc000
        if (jumpOffset >= oldOffset) {
          // Allow only pointers to prior data. RFC 1035, section 4.1.4 states:
          // "[...] an entire domain name or a list of labels at the end of a domain name
          // is replaced with a pointer to a prior occurance (sic) of the same name."
          throw new Error('Cannot decode name (bad pointer)')
        }
        offset = jumpOffset
        oldOffset = jumpOffset
        consumedBytes += jumped ? 0 : 1
        jumped = true
      } else {
        throw new Error('Cannot decode name (bad label)')
      }
    }

    name.decode.bytes = consumedBytes
    return list.length === 0 ? '.' : list.join('.')
  },
  encodingLength (n) {
    if (n === '.' || n === '..') return 1
    return Buffer.byteLength(n.replace(/^\.|\.$/gm, '')) + 2
  }
})

const string = codec({
  encode (s, buf, offset) {
    if (!buf) buf = Buffer.alloc(string.encodingLength(s))
    if (!offset) offset = 0

    const len = buf.write(s, offset + 1)
    buf[offset] = len
    string.encode.bytes = len + 1
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0

    const len = buf[offset]
    const s = buf.toString('utf-8', offset + 1, offset + 1 + len)
    string.decode.bytes = len + 1
    return s
  },
  encodingLength (s) {
    return Buffer.byteLength(s) + 1
  }
})

const header = codec({
  bytes: 12,
  encode (h, buf, offset) {
    if (!buf) buf = Buffer.alloc(header.encodingLength(h))
    if (!offset) offset = 0

    const flags = (h.flags || 0) & 32767
    const type = h.type === 'response' ? RESPONSE_FLAG : QUERY_FLAG

    buf.writeUInt16BE(h.id || 0, offset)
    buf.writeUInt16BE(flags | type, offset + 2)
    buf.writeUInt16BE(h.questions.length, offset + 4)
    buf.writeUInt16BE(h.answers.length, offset + 6)
    buf.writeUInt16BE(h.authorities.length, offset + 8)
    buf.writeUInt16BE(h.additionals.length, offset + 10)

    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0
    if (buf.length < 12) throw new Error('Header must be 12 bytes')
    const flags = buf.readUInt16BE(offset + 2)

    return {
      id: buf.readUInt16BE(offset),
      type: flags & RESPONSE_FLAG ? 'response' : 'query',
      flags: flags & 32767,
      flag_qr: ((flags >> 15) & 0x1) === 1,
      opcode: opcodes.toString((flags >> 11) & 0xf),
      flag_aa: ((flags >> 10) & 0x1) === 1,
      flag_tc: ((flags >> 9) & 0x1) === 1,
      flag_rd: ((flags >> 8) & 0x1) === 1,
      flag_ra: ((flags >> 7) & 0x1) === 1,
      flag_z: ((flags >> 6) & 0x1) === 1,
      flag_ad: ((flags >> 5) & 0x1) === 1,
      flag_cd: ((flags >> 4) & 0x1) === 1,
      rcode: rcodes.toString(flags & 0xf),
      questions: new Array(buf.readUInt16BE(offset + 4)),
      answers: new Array(buf.readUInt16BE(offset + 6)),
      authorities: new Array(buf.readUInt16BE(offset + 8)),
      additionals: new Array(buf.readUInt16BE(offset + 10))
    }
  },
  encodingLength () {
    return 12
  }
})

export const runknown = codec({
  encode (data, buf, offset) {
    if (!buf) buf = Buffer.alloc(runknown.encodingLength(data))
    if (!offset) offset = 0

    buf.writeUInt16BE(data.length, offset)
    data.copy(buf, offset + 2)

    runknown.encode.bytes = data.length + 2
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0

    const len = buf.readUInt16BE(offset)
    const data = buf.slice(offset + 2, offset + 2 + len)
    runknown.decode.bytes = len + 2
    return data
  },
  encodingLength (data) {
    return data.length + 2
  }
})

export const rns = codec({
  encode (data, buf, offset) {
    if (!buf) buf = Buffer.alloc(rns.encodingLength(data))
    if (!offset) offset = 0

    name.encode(data, buf, offset + 2)
    buf.writeUInt16BE(name.encode.bytes, offset)
    rns.encode.bytes = name.encode.bytes + 2
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0

    const len = buf.readUInt16BE(offset)
    const dd = name.decode(buf, offset + 2)

    rns.decode.bytes = len + 2
    return dd
  },
  encodingLength (data) {
    return name.encodingLength(data) + 2
  }
})

const rsoa = codec({
  encode (data, buf, offset) {
    if (!buf) buf = Buffer.alloc(rsoa.encodingLength(data))
    if (!offset) offset = 0

    const oldOffset = offset
    offset += 2
    name.encode(data.mname, buf, offset)
    offset += name.encode.bytes
    name.encode(data.rname, buf, offset)
    offset += name.encode.bytes
    buf.writeUInt32BE(data.serial || 0, offset)
    offset += 4
    buf.writeUInt32BE(data.refresh || 0, offset)
    offset += 4
    buf.writeUInt32BE(data.retry || 0, offset)
    offset += 4
    buf.writeUInt32BE(data.expire || 0, offset)
    offset += 4
    buf.writeUInt32BE(data.minimum || 0, offset)
    offset += 4

    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset)
    rsoa.encode.bytes = offset - oldOffset
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0

    const oldOffset = offset

    const data = {}
    offset += 2
    data.mname = name.decode(buf, offset)
    offset += name.decode.bytes
    data.rname = name.decode(buf, offset)
    offset += name.decode.bytes
    data.serial = buf.readUInt32BE(offset)
    offset += 4
    data.refresh = buf.readUInt32BE(offset)
    offset += 4
    data.retry = buf.readUInt32BE(offset)
    offset += 4
    data.expire = buf.readUInt32BE(offset)
    offset += 4
    data.minimum = buf.readUInt32BE(offset)
    offset += 4

    rsoa.decode.bytes = offset - oldOffset
    return data
  },
  encodingLength (data) {
    return 22 + name.encodingLength(data.mname) + name.encodingLength(data.rname)
  }
})

const rtxt = codec({
  encode (data, buf, offset) {
    if (!Array.isArray(data)) data = [data]
    for (let i = 0; i < data.length; i++) {
      if (typeof data[i] === 'string') {
        data[i] = Buffer.from(data[i])
      }
      if (!Buffer.isBuffer(data[i])) {
        throw new Error('Must be a Buffer')
      }
    }

    if (!buf) buf = Buffer.alloc(rtxt.encodingLength(data))
    if (!offset) offset = 0

    const oldOffset = offset
    offset += 2

    data.forEach(function (d) {
      buf[offset++] = d.length
      d.copy(buf, offset, 0, d.length)
      offset += d.length
    })

    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset)
    rtxt.encode.bytes = offset - oldOffset
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0
    const oldOffset = offset
    let remaining = buf.readUInt16BE(offset)
    offset += 2

    const data = []
    while (remaining > 0) {
      const len = buf[offset++]
      --remaining
      if (remaining < len) {
        throw new Error('Buffer overflow')
      }
      data.push(buf.slice(offset, offset + len))
      offset += len
      remaining -= len
    }

    rtxt.decode.bytes = offset - oldOffset
    return data
  },
  encodingLength (data) {
    if (!Array.isArray(data)) data = [data]
    let length = 2
    data.forEach(function (buf) {
      if (typeof buf === 'string') {
        length += Buffer.byteLength(buf) + 1
      } else {
        length += buf.length + 1
      }
    })
    return length
  }
})

const rnull = codec({
  encode (data, buf, offset) {
    if (!buf) buf = Buffer.alloc(rnull.encodingLength(data))
    if (!offset) offset = 0

    if (typeof data === 'string') data = Buffer.from(data)
    if (!data) data = Buffer.alloc(0)

    const oldOffset = offset
    offset += 2

    const len = data.length
    data.copy(buf, offset, 0, len)
    offset += len

    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset)
    rnull.encode.bytes = offset - oldOffset
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0
    const oldOffset = offset
    const len = buf.readUInt16BE(offset)

    offset += 2

    const data = buf.slice(offset, offset + len)
    offset += len

    rnull.decode.bytes = offset - oldOffset
    return data
  },
  encodingLength (data) {
    if (!data) return 2
    return (Buffer.isBuffer(data) ? data.length : Buffer.byteLength(data)) + 2
  }
})

const rhinfo = codec({
  encode (data, buf, offset) {
    if (!buf) buf = Buffer.alloc(rhinfo.encodingLength(data))
    if (!offset) offset = 0

    const oldOffset = offset
    offset += 2
    string.encode(data.cpu, buf, offset)
    offset += string.encode.bytes
    string.encode(data.os, buf, offset)
    offset += string.encode.bytes
    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset)
    rhinfo.encode.bytes = offset - oldOffset
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0

    const oldOffset = offset

    const data = {}
    offset += 2
    data.cpu = string.decode(buf, offset)
    offset += string.decode.bytes
    data.os = string.decode(buf, offset)
    offset += string.decode.bytes
    rhinfo.decode.bytes = offset - oldOffset
    return data
  },
  encodingLength (data) {
    return string.encodingLength(data.cpu) + string.encodingLength(data.os) + 2
  }
})

const rptr = codec({
  encode (data, buf, offset) {
    if (!buf) buf = Buffer.alloc(rptr.encodingLength(data))
    if (!offset) offset = 0

    name.encode(data, buf, offset + 2)
    buf.writeUInt16BE(name.encode.bytes, offset)
    rptr.encode.bytes = name.encode.bytes + 2
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0

    const data = name.decode(buf, offset + 2)
    rptr.decode.bytes = name.decode.bytes + 2
    return data
  },
  encodingLength (data) {
    return name.encodingLength(data) + 2
  }
})

const rsrv = codec({
  encode (data, buf, offset) {
    if (!buf) buf = Buffer.alloc(rsrv.encodingLength(data))
    if (!offset) offset = 0

    buf.writeUInt16BE(data.priority || 0, offset + 2)
    buf.writeUInt16BE(data.weight || 0, offset + 4)
    buf.writeUInt16BE(data.port || 0, offset + 6)
    name.encode(data.target, buf, offset + 8)

    const len = name.encode.bytes + 6
    buf.writeUInt16BE(len, offset)

    rsrv.encode.bytes = len + 2
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0

    const len = buf.readUInt16BE(offset)

    const data = {}
    data.priority = buf.readUInt16BE(offset + 2)
    data.weight = buf.readUInt16BE(offset + 4)
    data.port = buf.readUInt16BE(offset + 6)
    data.target = name.decode(buf, offset + 8)

    rsrv.decode.bytes = len + 2
    return data
  },
  encodingLength (data) {
    return 8 + name.encodingLength(data.target)
  }
})

const rcaa = codec({
  encode (data, buf, offset) {
    const len = rcaa.encodingLength(data)

    if (!buf) buf = Buffer.alloc(rcaa.encodingLength(data))
    if (!offset) offset = 0

    if (data.issuerCritical) {
      data.flags = rcaa.ISSUER_CRITICAL
    }

    buf.writeUInt16BE(len - 2, offset)
    offset += 2
    buf.writeUInt8(data.flags || 0, offset)
    offset += 1
    string.encode(data.tag, buf, offset)
    offset += string.encode.bytes
    buf.write(data.value, offset)
    offset += Buffer.byteLength(data.value)

    rcaa.encode.bytes = len
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0

    const len = buf.readUInt16BE(offset)
    offset += 2

    const oldOffset = offset
    const data = {}
    data.flags = buf.readUInt8(offset)
    offset += 1
    data.tag = string.decode(buf, offset)
    offset += string.decode.bytes
    data.value = buf.toString('utf-8', offset, oldOffset + len)

    data.issuerCritical = !!(data.flags & rcaa.ISSUER_CRITICAL)

    rcaa.decode.bytes = len + 2

    return data
  },
  encodingLength (data) {
    return string.encodingLength(data.tag) + string.encodingLength(data.value) + 2
  }
})

rcaa.ISSUER_CRITICAL = 1 << 7

const rmx = codec({
  encode (data, buf, offset) {
    if (!buf) buf = Buffer.alloc(rmx.encodingLength(data))
    if (!offset) offset = 0

    const oldOffset = offset
    offset += 2
    buf.writeUInt16BE(data.preference || 0, offset)
    offset += 2
    name.encode(data.exchange, buf, offset)
    offset += name.encode.bytes

    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset)
    rmx.encode.bytes = offset - oldOffset
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0

    const oldOffset = offset

    const data = {}
    offset += 2
    data.preference = buf.readUInt16BE(offset)
    offset += 2
    data.exchange = name.decode(buf, offset)
    offset += name.decode.bytes

    rmx.decode.bytes = offset - oldOffset
    return data
  },
  encodingLength (data) {
    return 4 + name.encodingLength(data.exchange)
  }
})

const ra = codec({
  encode (host, buf, offset) {
    if (!buf) buf = Buffer.alloc(ra.encodingLength(host))
    if (!offset) offset = 0

    buf.writeUInt16BE(4, offset)
    offset += 2
    ip.v4.encode(host, buf, offset)
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0

    offset += 2
    const host = ip.v4.decode(buf, offset)
    return host
  },
  bytes: 6
})

const raaaa = codec({
  encode (host, buf, offset) {
    if (!buf) buf = Buffer.alloc(raaaa.encodingLength(host))
    if (!offset) offset = 0

    buf.writeUInt16BE(16, offset)
    offset += 2
    ip.v6.encode(host, buf, offset)
    raaaa.encode.bytes = 18
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0

    offset += 2
    const host = ip.v6.decode(buf, offset)
    raaaa.decode.bytes = 18
    return host
  },
  bytes: 18
})

const roption = codec({
  encode (option, buf, offset) {
    if (!buf) buf = Buffer.alloc(roption.encodingLength(option))
    if (!offset) offset = 0
    const oldOffset = offset

    const code = optioncodes.toCode(option.code)
    buf.writeUInt16BE(code, offset)
    offset += 2
    if (option.data) {
      buf.writeUInt16BE(option.data.length, offset)
      offset += 2
      option.data.copy(buf, offset)
      offset += option.data.length
    } else {
      switch (code) {
        // case 3: NSID.  No encode makes sense.
        // case 5,6,7: Not implementable
        case 8: // ECS
          {
            // note: do IP math before calling
            const spl = option.sourcePrefixLength || 0
            const fam = option.family || ip.familyOf(option.ip)
            const ipBuf = ip.encode(option.ip, Buffer.alloc)
            const ipLen = Math.ceil(spl / 8)
            buf.writeUInt16BE(ipLen + 4, offset)
            offset += 2
            buf.writeUInt16BE(fam, offset)
            offset += 2
            buf.writeUInt8(spl, offset++)
            buf.writeUInt8(option.scopePrefixLength || 0, offset++)

            ipBuf.copy(buf, offset, 0, ipLen)
            offset += ipLen
          }
          break
        // case 9: EXPIRE (experimental)
        // case 10: COOKIE.  No encode makes sense.
        case 11: // KEEP-ALIVE
          if (option.timeout) {
            buf.writeUInt16BE(2, offset)
            offset += 2
            buf.writeUInt16BE(option.timeout, offset)
            offset += 2
          } else {
            buf.writeUInt16BE(0, offset)
            offset += 2
          }
          break
        case 12: // PADDING
          {
            const len = option.length || 0
            buf.writeUInt16BE(len, offset)
            offset += 2
            buf.fill(0, offset, offset + len)
            offset += len
          }
          break
        // case 13:  CHAIN.  Experimental.
        case 14: // KEY-TAG
          {
            const tagsLen = option.tags.length * 2
            buf.writeUInt16BE(tagsLen, offset)
            offset += 2
            for (const tag of option.tags) {
              buf.writeUInt16BE(tag, offset)
              offset += 2
            }
          }
          break
        default:
          throw new Error(`Unknown roption code: ${option.code}`)
      }
    }

    roption.encode.bytes = offset - oldOffset
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0
    const option = {}
    option.code = buf.readUInt16BE(offset)
    option.type = optioncodes.toString(option.code)
    offset += 2
    const len = buf.readUInt16BE(offset)
    offset += 2
    option.data = buf.slice(offset, offset + len)
    switch (option.code) {
      // case 3: NSID.  No decode makes sense.
      case 8: // ECS
        option.family = buf.readUInt16BE(offset)
        offset += 2
        option.sourcePrefixLength = buf.readUInt8(offset++)
        option.scopePrefixLength = buf.readUInt8(offset++)
        {
          const padded = Buffer.alloc((option.family === 1) ? 4 : 16)
          buf.copy(padded, 0, offset, offset + len - 4)
          option.ip = ip.decode(padded)
        }
        break
      // case 12: Padding.  No decode makes sense.
      case 11: // KEEP-ALIVE
        if (len > 0) {
          option.timeout = buf.readUInt16BE(offset)
          offset += 2
        }
        break
      case 14:
        option.tags = []
        for (let i = 0; i < len; i += 2) {
          option.tags.push(buf.readUInt16BE(offset))
          offset += 2
        }
      // don't worry about default.  caller will use data if desired
    }

    roption.decode.bytes = len + 4
    return option
  },
  encodingLength (option) {
    if (option.data) {
      return option.data.length + 4
    }
    const code = optioncodes.toCode(option.code)
    switch (code) {
      case 8: // ECS
      {
        const spl = option.sourcePrefixLength || 0
        return Math.ceil(spl / 8) + 8
      }
      case 11: // KEEP-ALIVE
        return (typeof option.timeout === 'number') ? 6 : 4
      case 12: // PADDING
        return option.length + 4
      case 14: // KEY-TAG
        return 4 + (option.tags.length * 2)
    }
    throw new Error(`Unknown roption code: ${option.code}`)
  }
})

const ropt = codec({
  encode (options, buf, offset) {
    if (!buf) buf = Buffer.alloc(ropt.encodingLength(options))
    if (!offset) offset = 0
    const oldOffset = offset

    const rdlen = encodingLengthList(options, roption)
    buf.writeUInt16BE(rdlen, offset)
    offset = encodeList(options, roption, buf, offset + 2)

    ropt.encode.bytes = offset - oldOffset
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0
    const oldOffset = offset

    const options = []
    let rdlen = buf.readUInt16BE(offset)
    offset += 2
    let o = 0
    while (rdlen > 0) {
      options[o++] = roption.decode(buf, offset)
      offset += roption.decode.bytes
      rdlen -= roption.decode.bytes
    }
    ropt.decode.bytes = offset - oldOffset
    return options
  },
  encodingLength (options) {
    return 2 + encodingLengthList(options || [], roption)
  }
})

const rdnskey = codec({
  encode (key, buf, offset) {
    if (!buf) buf = Buffer.alloc(rdnskey.encodingLength(key))
    if (!offset) offset = 0
    const oldOffset = offset

    const keydata = key.key
    if (!Buffer.isBuffer(keydata)) {
      throw new Error('Key must be a Buffer')
    }

    offset += 2 // Leave space for length
    buf.writeUInt16BE(key.flags, offset)
    offset += 2
    buf.writeUInt8(rdnskey.PROTOCOL_DNSSEC, offset)
    offset += 1
    buf.writeUInt8(key.algorithm, offset)
    offset += 1
    keydata.copy(buf, offset, 0, keydata.length)
    offset += keydata.length

    rdnskey.encode.bytes = offset - oldOffset
    buf.writeUInt16BE(rdnskey.encode.bytes - 2, oldOffset)
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0
    const oldOffset = offset

    const key = {}
    const length = buf.readUInt16BE(offset)
    offset += 2
    key.flags = buf.readUInt16BE(offset)
    offset += 2
    if (buf.readUInt8(offset) !== rdnskey.PROTOCOL_DNSSEC) {
      throw new Error('Protocol must be 3')
    }
    offset += 1
    key.algorithm = buf.readUInt8(offset)
    offset += 1
    key.key = buf.slice(offset, oldOffset + length + 2)
    offset += key.key.length
    rdnskey.decode.bytes = offset - oldOffset
    return key
  },
  encodingLength (key) {
    return 6 + Buffer.byteLength(key.key)
  }
})

rdnskey.PROTOCOL_DNSSEC = 3
rdnskey.ZONE_KEY = 0x80
rdnskey.SECURE_ENTRYPOINT = 0x8000

const rrrsig = codec({
  encode (sig, buf, offset) {
    if (!buf) buf = Buffer.alloc(rrrsig.encodingLength(sig))
    if (!offset) offset = 0
    const oldOffset = offset

    const signature = sig.signature
    if (!Buffer.isBuffer(signature)) {
      throw new Error('Signature must be a Buffer')
    }

    offset += 2 // Leave space for length
    buf.writeUInt16BE(types.toType(sig.typeCovered), offset)
    offset += 2
    buf.writeUInt8(sig.algorithm, offset)
    offset += 1
    buf.writeUInt8(sig.labels, offset)
    offset += 1
    buf.writeUInt32BE(sig.originalTTL, offset)
    offset += 4
    buf.writeUInt32BE(sig.expiration, offset)
    offset += 4
    buf.writeUInt32BE(sig.inception, offset)
    offset += 4
    buf.writeUInt16BE(sig.keyTag, offset)
    offset += 2
    name.encode(sig.signersName, buf, offset)
    offset += name.encode.bytes
    signature.copy(buf, offset, 0, signature.length)
    offset += signature.length

    rrrsig.encode.bytes = offset - oldOffset
    buf.writeUInt16BE(rrrsig.encode.bytes - 2, oldOffset)
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0
    const oldOffset = offset

    const sig = {}
    const length = buf.readUInt16BE(offset)
    offset += 2
    sig.typeCovered = types.toString(buf.readUInt16BE(offset))
    offset += 2
    sig.algorithm = buf.readUInt8(offset)
    offset += 1
    sig.labels = buf.readUInt8(offset)
    offset += 1
    sig.originalTTL = buf.readUInt32BE(offset)
    offset += 4
    sig.expiration = buf.readUInt32BE(offset)
    offset += 4
    sig.inception = buf.readUInt32BE(offset)
    offset += 4
    sig.keyTag = buf.readUInt16BE(offset)
    offset += 2
    sig.signersName = name.decode(buf, offset)
    offset += name.decode.bytes
    sig.signature = buf.slice(offset, oldOffset + length + 2)
    offset += sig.signature.length
    rrrsig.decode.bytes = offset - oldOffset
    return sig
  },
  encodingLength (sig) {
    return 20 +
      name.encodingLength(sig.signersName) +
      Buffer.byteLength(sig.signature)
  }
})
const rrp = codec({
  encode (data, buf, offset) {
    if (!buf) buf = Buffer.alloc(rrp.encodingLength(data))
    if (!offset) offset = 0
    const oldOffset = offset

    offset += 2 // Leave space for length
    name.encode(data.mbox || '.', buf, offset)
    offset += name.encode.bytes
    name.encode(data.txt || '.', buf, offset)
    offset += name.encode.bytes
    rrp.encode.bytes = offset - oldOffset
    buf.writeUInt16BE(rrp.encode.bytes - 2, oldOffset)
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0
    const oldOffset = offset

    const data = {}
    offset += 2
    data.mbox = name.decode(buf, offset) || '.'
    offset += name.decode.bytes
    data.txt = name.decode(buf, offset) || '.'
    offset += name.decode.bytes
    rrp.decode.bytes = offset - oldOffset
    return data
  },
  encodingLength (data) {
    return 2 + name.encodingLength(data.mbox || '.') + name.encodingLength(data.txt || '.')
  }
})

const typebitmap = codec({
  encode (typelist, buf, offset) {
    if (!buf) buf = Buffer.alloc(typebitmap.encodingLength(typelist))
    if (!offset) offset = 0
    const oldOffset = offset

    const typesByWindow = []
    for (let i = 0; i < typelist.length; i++) {
      const typeid = types.toType(typelist[i])
      if (typesByWindow[typeid >> 8] === undefined) {
        typesByWindow[typeid >> 8] = []
      }
      typesByWindow[typeid >> 8][(typeid >> 3) & 0x1F] |= 1 << (7 - (typeid & 0x7))
    }

    for (let i = 0; i < typesByWindow.length; i++) {
      if (typesByWindow[i] !== undefined) {
        const windowBuf = Buffer.from(typesByWindow[i])
        buf.writeUInt8(i, offset)
        offset += 1
        buf.writeUInt8(windowBuf.length, offset)
        offset += 1
        windowBuf.copy(buf, offset)
        offset += windowBuf.length
      }
    }

    typebitmap.encode.bytes = offset - oldOffset
    return buf
  },
  decode (buf, offset, length) {
    if (!offset) offset = 0
    const oldOffset = offset

    const typelist = []
    while (offset - oldOffset < length) {
      const window = buf.readUInt8(offset)
      offset += 1
      const windowLength = buf.readUInt8(offset)
      offset += 1
      for (let i = 0; i < windowLength; i++) {
        const b = buf.readUInt8(offset + i)
        for (let j = 0; j < 8; j++) {
          if (b & (1 << (7 - j))) {
            const typeid = types.toString((window << 8) | (i << 3) | j)
            typelist.push(typeid)
          }
        }
      }
      offset += windowLength
    }

    typebitmap.decode.bytes = offset - oldOffset
    return typelist
  },
  encodingLength (typelist) {
    const extents = []
    for (let i = 0; i < typelist.length; i++) {
      const typeid = types.toType(typelist[i])
      extents[typeid >> 8] = Math.max(extents[typeid >> 8] || 0, typeid & 0xFF)
    }

    let len = 0
    for (let i = 0; i < extents.length; i++) {
      if (extents[i] !== undefined) {
        len += 2 + Math.ceil((extents[i] + 1) / 8)
      }
    }

    return len
  }
})

const rnsec = codec({
  encode (record, buf, offset) {
    if (!buf) buf = Buffer.alloc(rnsec.encodingLength(record))
    if (!offset) offset = 0
    const oldOffset = offset

    offset += 2 // Leave space for length
    name.encode(record.nextDomain, buf, offset)
    offset += name.encode.bytes
    typebitmap.encode(record.rrtypes, buf, offset)
    offset += typebitmap.encode.bytes

    rnsec.encode.bytes = offset - oldOffset
    buf.writeUInt16BE(rnsec.encode.bytes - 2, oldOffset)
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0
    const oldOffset = offset

    const record = {}
    const length = buf.readUInt16BE(offset)
    offset += 2
    record.nextDomain = name.decode(buf, offset)
    offset += name.decode.bytes
    record.rrtypes = typebitmap.decode(buf, offset, length - (offset - oldOffset))
    offset += typebitmap.decode.bytes

    rnsec.decode.bytes = offset - oldOffset
    return record
  },
  encodingLength (record) {
    return 2 +
      name.encodingLength(record.nextDomain) +
      typebitmap.encodingLength(record.rrtypes)
  }
})

const rnsec3 = codec({
  encode (record, buf, offset) {
    if (!buf) buf = Buffer.alloc(rnsec3.encodingLength(record))
    if (!offset) offset = 0
    const oldOffset = offset

    const salt = record.salt
    if (!Buffer.isBuffer(salt)) {
      throw new Error('salt must be a Buffer')
    }

    const nextDomain = record.nextDomain
    if (!Buffer.isBuffer(nextDomain)) {
      throw new Error('nextDomain must be a Buffer')
    }

    offset += 2 // Leave space for length
    buf.writeUInt8(record.algorithm, offset)
    offset += 1
    buf.writeUInt8(record.flags, offset)
    offset += 1
    buf.writeUInt16BE(record.iterations, offset)
    offset += 2
    buf.writeUInt8(salt.length, offset)
    offset += 1
    salt.copy(buf, offset, 0, salt.length)
    offset += salt.length
    buf.writeUInt8(nextDomain.length, offset)
    offset += 1
    nextDomain.copy(buf, offset, 0, nextDomain.length)
    offset += nextDomain.length
    typebitmap.encode(record.rrtypes, buf, offset)
    offset += typebitmap.encode.bytes

    rnsec3.encode.bytes = offset - oldOffset
    buf.writeUInt16BE(rnsec3.encode.bytes - 2, oldOffset)
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0
    const oldOffset = offset

    const record = {}
    const length = buf.readUInt16BE(offset)
    offset += 2
    record.algorithm = buf.readUInt8(offset)
    offset += 1
    record.flags = buf.readUInt8(offset)
    offset += 1
    record.iterations = buf.readUInt16BE(offset)
    offset += 2
    const saltLength = buf.readUInt8(offset)
    offset += 1
    record.salt = buf.slice(offset, offset + saltLength)
    offset += saltLength
    const hashLength = buf.readUInt8(offset)
    offset += 1
    record.nextDomain = buf.slice(offset, offset + hashLength)
    offset += hashLength
    record.rrtypes = typebitmap.decode(buf, offset, length - (offset - oldOffset))
    offset += typebitmap.decode.bytes

    rnsec3.decode.bytes = offset - oldOffset
    return record
  },
  encodingLength (record) {
    return 8 +
      record.salt.length +
      record.nextDomain.length +
      typebitmap.encodingLength(record.rrtypes)
  }
})

const rds = codec({
  encode (digest, buf, offset) {
    if (!buf) buf = Buffer.alloc(rds.encodingLength(digest))
    if (!offset) offset = 0
    const oldOffset = offset

    const digestdata = digest.digest
    if (!Buffer.isBuffer(digestdata)) {
      throw new Error('Digest must be a Buffer')
    }

    offset += 2 // Leave space for length
    buf.writeUInt16BE(digest.keyTag, offset)
    offset += 2
    buf.writeUInt8(digest.algorithm, offset)
    offset += 1
    buf.writeUInt8(digest.digestType, offset)
    offset += 1
    digestdata.copy(buf, offset, 0, digestdata.length)
    offset += digestdata.length

    rds.encode.bytes = offset - oldOffset
    buf.writeUInt16BE(rds.encode.bytes - 2, oldOffset)
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0
    const oldOffset = offset

    const digest = {}
    const length = buf.readUInt16BE(offset)
    offset += 2
    digest.keyTag = buf.readUInt16BE(offset)
    offset += 2
    digest.algorithm = buf.readUInt8(offset)
    offset += 1
    digest.digestType = buf.readUInt8(offset)
    offset += 1
    digest.digest = buf.slice(offset, oldOffset + length + 2)
    offset += digest.digest.length
    rds.decode.bytes = offset - oldOffset
    return digest
  },
  encodingLength (digest) {
    return 6 + Buffer.byteLength(digest.digest)
  }
})

function renc (type) {
  switch (type.toUpperCase()) {
    case 'A': return ra
    case 'PTR': return rptr
    case 'CNAME': return rptr
    case 'DNAME': return rptr
    case 'TXT': return rtxt
    case 'NULL': return rnull
    case 'AAAA': return raaaa
    case 'SRV': return rsrv
    case 'HINFO': return rhinfo
    case 'CAA': return rcaa
    case 'NS': return rns
    case 'SOA': return rsoa
    case 'MX': return rmx
    case 'OPT': return ropt
    case 'DNSKEY': return rdnskey
    case 'RRSIG': return rrrsig
    case 'RP': return rrp
    case 'NSEC': return rnsec
    case 'NSEC3': return rnsec3
    case 'DS': return rds
  }
  return runknown
}

export const answer = codec({
  encode (a, buf, offset) {
    if (!buf) buf = Buffer.alloc(answer.encodingLength(a))
    if (!offset) offset = 0

    const oldOffset = offset

    name.encode(a.name, buf, offset)
    offset += name.encode.bytes

    buf.writeUInt16BE(types.toType(a.type), offset)

    if (a.type.toUpperCase() === 'OPT') {
      if (a.name !== '.') {
        throw new Error('OPT name must be root.')
      }
      buf.writeUInt16BE(a.udpPayloadSize || 4096, offset + 2)
      buf.writeUInt8(a.extendedRcode || 0, offset + 4)
      buf.writeUInt8(a.ednsVersion || 0, offset + 5)
      buf.writeUInt16BE(a.flags || 0, offset + 6)

      offset += 8
      ropt.encode(a.options || [], buf, offset)
      offset += ropt.encode.bytes
    } else {
      let klass = classes.toClass(a.class === undefined ? 'IN' : a.class)
      if (a.flush) klass |= FLUSH_MASK // the 1st bit of the class is the flush bit
      buf.writeUInt16BE(klass, offset + 2)
      buf.writeUInt32BE(a.ttl || 0, offset + 4)

      offset += 8
      const enc = renc(a.type)
      enc.encode(a.data, buf, offset)
      offset += enc.encode.bytes
    }

    answer.encode.bytes = offset - oldOffset
    return buf
  },
  decode (buf, offset) {
    if (!offset) offset = 0

    const a = {}
    const oldOffset = offset

    a.name = name.decode(buf, offset)
    offset += name.decode.bytes
    a.type = types.toString(buf.readUInt16BE(offset))
    if (a.type === 'OPT') {
      a.udpPayloadSize = buf.readUInt16BE(offset + 2)
      a.extendedRcode = buf.readUInt8(offset + 4)
      a.ednsVersion = buf.readUInt8(offset + 5)
      a.flags = buf.readUInt16BE(offset + 6)
      a.flag_do = ((a.flags >> 15) & 0x1) === 1
      a.options = ropt.decode(buf, offset + 8)
      offset += 8 + ropt.decode.bytes
    } else {
      const klass = buf.readUInt16BE(offset + 2)
      a.ttl = buf.readUInt32BE(offset + 4)

      a.class = classes.toString(klass & NOT_FLUSH_MASK)
      a.flush = !!(klass & FLUSH_MASK)

      const enc = renc(a.type)
      a.data = enc.decode(buf, offset + 8)
      offset += 8 + enc.decode.bytes
    }

    answer.decode.bytes = offset - oldOffset
    return a
  },
  encodingLength (a) {
    const data = (a.data !== null && a.data !== undefined) ? a.data : a.options
    return name.encodingLength(a.name) + 8 + renc(a.type).encodingLength(data)
  }
})

export const question = codec({
  encode (q, buf, offset) {
    if (!buf) buf = Buffer.alloc(question.encodingLength(q))
    if (!offset) offset = 0

    const oldOffset = offset

    name.encode(q.name, buf, offset)
    offset += name.encode.bytes

    buf.writeUInt16BE(types.toType(q.type), offset)
    offset += 2

    buf.writeUInt16BE(classes.toClass(q.class === undefined ? 'IN' : q.class), offset)
    offset += 2

    question.encode.bytes = offset - oldOffset
    return q
  },
  decode (buf, offset) {
    if (!offset) offset = 0

    const oldOffset = offset
    const q = {}

    q.name = name.decode(buf, offset)
    offset += name.decode.bytes

    q.type = types.toString(buf.readUInt16BE(offset))
    offset += 2

    q.class = classes.toString(buf.readUInt16BE(offset))
    offset += 2

    const qu = !!(q.class & QU_MASK)
    if (qu) q.class &= NOT_QU_MASK

    question.decode.bytes = offset - oldOffset
    return q
  },
  encodingLength (q) {
    return name.encodingLength(q.name) + 4
  }
})

export {
  rsoa as soa,
  rtxt as txt,
  rnull as null,
  runknown as unknown,
  rns as ns,
  rhinfo as hinfo,
  rptr as ptr,
  rptr as cname,
  rptr as dname,
  rsrv as srv,
  rcaa as caa,
  rmx as mx,
  ra as a,
  raaaa as aaaa,
  roption as option,
  ropt as opt,
  rdnskey as dnskey,
  rrrsig as rrsig,
  rrp as rp,
  rnsec as nsec,
  rnsec3 as nsec3,
  rds as ds,
  renc as enc
}

export const AUTHORITATIVE_ANSWER = 1 << 10
export const TRUNCATED_RESPONSE = 1 << 9
export const RECURSION_DESIRED = 1 << 8
export const RECURSION_AVAILABLE = 1 << 7
export const AUTHENTIC_DATA = 1 << 5
export const CHECKING_DISABLED = 1 << 4
export const DNSSEC_OK = 1 << 15

export function encode (result, buf, offset) {
  const allocing = !buf

  if (allocing) buf = Buffer.alloc(encodingLength(result))
  if (!offset) offset = 0

  const oldOffset = offset

  if (!result.questions) result.questions = []
  if (!result.answers) result.answers = []
  if (!result.authorities) result.authorities = []
  if (!result.additionals) result.additionals = []

  header.encode(result, buf, offset)
  offset += header.encode.bytes

  offset = encodeList(result.questions, question, buf, offset)
  offset = encodeList(result.answers, answer, buf, offset)
  offset = encodeList(result.authorities, answer, buf, offset)
  offset = encodeList(result.additionals, answer, buf, offset)

  encode.bytes = offset - oldOffset

  // just a quick sanity check
  if (allocing && encode.bytes !== buf.length) {
    return buf.slice(0, encode.bytes)
  }

  return buf
}
encode.bytes = 0

export function decode (buf, offset) {
  if (!offset) offset = 0

  const oldOffset = offset
  const result = header.decode(buf, offset)
  offset += header.decode.bytes

  offset = decodeList(result.questions, question, buf, offset)
  offset = decodeList(result.answers, answer, buf, offset)
  offset = decodeList(result.authorities, answer, buf, offset)
  offset = decodeList(result.additionals, answer, buf, offset)

  decode.bytes = offset - oldOffset

  return result
}
decode.bytes = 0

export function encodingLength (result) {
  return header.encodingLength(result) +
    encodingLengthList(result.questions || [], question) +
    encodingLengthList(result.answers || [], answer) +
    encodingLengthList(result.authorities || [], answer) +
    encodingLengthList(result.additionals || [], answer)
}

export function streamEncode (result) {
  const buf = encode(result)
  const sbuf = Buffer.alloc(2)
  sbuf.writeUInt16BE(buf.byteLength)
  const combine = Buffer.concat([sbuf, buf])
  streamEncode.bytes = combine.byteLength
  return combine
}
streamEncode.bytes = 0

export function streamDecode (sbuf) {
  const len = sbuf.readUInt16BE(0)
  if (sbuf.byteLength < len + 2) {
    // not enough data
    return null
  }
  const result = decode(sbuf.slice(2))
  streamDecode.bytes = decode.bytes
  return result
}
streamDecode.bytes = 0

export function encodingLengthList (list, enc) {
  let len = 0
  for (let i = 0; i < list.length; i++) len += enc.encodingLength(list[i])
  return len
}

export function encodeList (list, enc, buf, offset) {
  for (let i = 0; i < list.length; i++) {
    enc.encode(list[i], buf, offset)
    offset += enc.encode.bytes
  }
  return offset
}

export function decodeList (list, enc, buf, offset) {
  for (let i = 0; i < list.length; i++) {
    list[i] = enc.decode(buf, offset)
    offset += enc.decode.bytes
  }
  return offset
}
