import * as dnsPacket from '@leichtgewicht/dns-packet';
import { Codec, UnknownCodec } from '@leichtgewicht/dns-packet';
import { Buffer } from 'buffer';

dnsPacket.decode(dnsPacket.encode({
  id: 1,
  type: 'query',
  questions: [
    {
      name: 'test',
      type: 'A'
    },
    {
      name: 'foo',
      type: 'boo'
    }
  ]
}));

const num: number[] = [
  dnsPacket.AUTHENTIC_DATA,
  dnsPacket.AUTHORITATIVE_ANSWER,
  dnsPacket.CHECKING_DISABLED,
  dnsPacket.DNSSEC_OK,
  dnsPacket.RECURSION_AVAILABLE,
  dnsPacket.RECURSION_DESIRED,
  dnsPacket.TRUNCATED_RESPONSE,
  dnsPacket.dnskey.PROTOCOL_DNSSEC,
  dnsPacket.dnskey.ZONE_KEY,
  dnsPacket.dnskey.SECURE_ENTRYPOINT,
  dnsPacket.encodingLength({}),
  dnsPacket.encodingLengthList([], dnsPacket.a)
];

const codec: Array<Codec<any>> = [
  dnsPacket.a,
  dnsPacket.aaaa,
  dnsPacket.answer,
  dnsPacket.caa,
  dnsPacket.cname,
  dnsPacket.dname,
  dnsPacket.dnskey,
  dnsPacket.ds,
  dnsPacket.hinfo,
  dnsPacket.mx,
  dnsPacket.name,
  dnsPacket.ns,
  dnsPacket.nsec,
  dnsPacket.nsec3,
  dnsPacket.null,
  dnsPacket.opt,
  dnsPacket.option,
  dnsPacket.ptr,
  dnsPacket.question,
  dnsPacket.rp,
  dnsPacket.rrsig,
  dnsPacket.soa,
  dnsPacket.srv,
  dnsPacket.txt,
  dnsPacket.unknown
];

const unknownCodecs: Array<UnknownCodec> = [
  dnsPacket.unknown,
  dnsPacket.enc('hello')
];

const decoded = dnsPacket.decode(Buffer.from('abcd'));
const decodedList = dnsPacket.decodeList([], dnsPacket.a, Buffer.alloc(0));
dnsPacket.streamDecode(Buffer.alloc(0));
const buff: Buffer = dnsPacket.streamEncode({});
