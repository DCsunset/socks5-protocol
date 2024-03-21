/**
 * socks5-protocol
 * Copyright 2024 DCsunset
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { stat } from "fs";
import ip, { isV4Format } from "ip";

const SOCKS_VERSION = 0x05;

export function isValidUInt(num: number, max: number): boolean {
  return Number.isInteger(num) && num >= 0 && num <= max;
}

export class SocksError extends Error {
  constructor(msg: string) {
    super(msg);
  }
}

// Auth

export enum AuthMethod {
  NO_AUTH = 0x00,
  GSSAPI = 0x01,
  USER_PASS = 0x02,
  NO_ACCEPT = 0xff
};

export type AuthReq = {
  methods: number[];
}

export function encodeAuthReq({ methods }: AuthReq): Buffer {
  if (methods.length > 0xff) {
    throw new SocksError("Invalid length for AuthReq");
  }
  return Buffer.from([
    SOCKS_VERSION,
    methods.length,
    ...methods
  ]);
}

export function decodeAuthReq(buf: Buffer): AuthReq {
  if (
    buf.length < 3
      || buf[0] !== SOCKS_VERSION
      || buf.length !== buf[1] + 2
  ) {
    throw new SocksError("Invalid AuthReq");
  }
  return { methods: [...buf.subarray(2)] };
}

export type AuthResp = {
  method: number;
}

export function encodeAuthResp({ method }: AuthResp): Buffer {
  if (!isValidUInt(method, 0xff)) {
    throw new SocksError("Invalid AuthResp");
  }
  return Buffer.from([SOCKS_VERSION, method]);
}

export function decodeAuthResp(buf: Buffer): AuthResp {
  if (
    buf.length !== 2
      || buf[0] !== SOCKS_VERSION
  ) {
    throw new SocksError("Invalid AuthResp");
  }
  return { method: buf[1] };
}


// Socks Addr

export enum SocksAddrType {
  IPv4 = 0x01,
  Domain = 0x03,
  IPv6 = 0x04
}

export type SocksAddr = {
  type: SocksAddrType,
  addr: string
}

// Create a minimum dummy socks addr
export function dummySocksAddr() {
  return {
    type: SocksAddrType.Domain,
    addr: ""
  };
};

export function sizeofSocksAddr({ type, addr }: SocksAddr): number {
  switch (type) {
    case SocksAddrType.IPv4:
      return 1 + 4;
    case SocksAddrType.IPv6:
      return 1 + 16;
    case SocksAddrType.Domain:
      if (addr.length > 0xff) {
        throw new SocksError("Invalid domain for SocksAddr: length is too long");
      }
      return 1 + 1 + addr.length;
    default:
      throw new SocksError(`Invalid type for SocksAddr: ${type}`);
  }
}

export function encodePort(port: number): Buffer {
  if (!isValidUInt(port, 0xffff)) {
    throw new SocksError(`Invalid port: ${port}`);
  }
  const portBuf = Buffer.allocUnsafe(2);
  portBuf.writeUint16BE(port);
  return portBuf;
}

export function encodeSocksAddr({ type, addr }: SocksAddr): Buffer {
  let addrBuf: Buffer;
  switch (type) {
    case SocksAddrType.IPv4:
    case SocksAddrType.IPv6:
      addrBuf = ip.toBuffer(addr);
      break;
    case SocksAddrType.Domain:
      addrBuf = Buffer.from(addr);
      break;
    default:
      throw new SocksError(`Invalid type for SocksAddr: ${type}`);
  }
  return Buffer.concat([
    Buffer.from([type]),
    addrBuf
  ]);
}

/**
 * Note: extra buffer won't be consumed
 *
 * offset is used for performance (without copying the buffer)
 */
export function decodeSocksAddr(buf: Buffer, offset = 0): SocksAddr {
  if (buf.length < offset + 2) {
    throw new SocksError("Invalid SocksAddr buffer");
  }
  const type = buf[offset];
  let addr: string;
  switch (type) {
    case SocksAddrType.IPv4:
      if (buf.length < offset + 5) {
        throw new SocksError("Invalid SocksAddr buffer");
      }
      addr = ip.toString(buf, offset + 1);
      break;
    case SocksAddrType.IPv6:
      if (buf.length < offset + 17) {
        throw new SocksError("Invalid length for SocksAddr");
      }
      addr = ip.toString(buf, offset + 1);
      break;
    case SocksAddrType.Domain:
      const len = buf[1];
      if (buf.length < offset + len + 2) {
        throw new SocksError("Invalid SocksAddr buffer");
      }
      addr = buf.subarray(offset + 2, offset + len + 2).toString();
      break;
    default:
      throw new SocksError(`Invalid type for SocksAddr buffer: ${type}`);
  }
  return { type, addr };
}

export function decodeSocksAddrPort(buf: Buffer, offset = 0): [SocksAddr, number] {
  const addr = decodeSocksAddr(buf, offset);
  const addrSize = sizeofSocksAddr(addr);
  if (buf.length < offset + addrSize + 2) {
    throw new SocksError("Invalid SocksAddr or Port");
  }
  const port = buf.readUInt16BE(offset + addrSize);
  return [addr, port];
}


// Connection

export enum ConnCmd {
  TCP_CONNECT = 0x01,
  TCP_BIND = 0x02,
  UDP_ASSOC = 0x03
}

export type ConnReq = {
  cmd: ConnCmd,
  dstAddr: SocksAddr,
  dstPort: number
}

export function encodeConnReq({ cmd, dstAddr, dstPort }: ConnReq): Buffer {
  if (!(cmd in ConnCmd)) {
    throw new SocksError("Invalid ConnReq");
  }
  return Buffer.concat([
    Buffer.from([
      SOCKS_VERSION,
      cmd,
      0x00
    ]),
    encodeSocksAddr(dstAddr),
    encodePort(dstPort)
  ]);
}

export function decodeConnReq(buf: Buffer): ConnReq {
  if (
    buf.length < 5 + 2
      || buf[0] !== SOCKS_VERSION
      || !(buf[1] in ConnCmd)
      || buf[2] !== 0x00
  ) {
    throw new SocksError("Invalid ConnReq buffer");
  }

  const cmd = buf[1];
  const [dstAddr, dstPort] = decodeSocksAddrPort(buf, 3);

  return {
    cmd,
    dstAddr,
    dstPort
  };
}

export enum ConnStatus {
  SUCCESS = 0x00,
  FAILURE = 0x01,
  CONN_DISALLOWED = 0x02,
  NET_UNREACHABLE = 0x03,
  HOST_UNREACHABLE = 0x04,
  CONN_REFUSED = 0x05,
  EXPIRED = 0x06,
  UNSUPPORTED = 0x07,
  ADDR_INVALID = 0x08
};

export type ConnResp = {
  status: ConnStatus.SUCCESS,
  bndAddr: SocksAddr,
  bndPort: number
} | {
  status: Exclude<ConnStatus, ConnStatus.SUCCESS>
};

export function encodeConnResp(resp: ConnResp): Buffer {
  const { status } = resp;
  if (!isValidUInt(status, 0xff)) {
    throw new SocksError("Invalid ConnResp");
  }

  let bndAddr: SocksAddr;
  let bndPort: number;
  if (resp.status !== ConnStatus.SUCCESS) {
    // Contruct minimum dummy address
    bndAddr = dummySocksAddr();
    bndPort = 0;
  }
  else {
    ({ bndAddr, bndPort } = resp);
  }

  return Buffer.concat([
    Buffer.from([ SOCKS_VERSION, status, 0x00 ]),
    encodeSocksAddr(bndAddr),
    encodePort(bndPort)
  ]);
}

export function decodeConnResp(buf: Buffer): ConnResp {
  if (
    buf.length < 5 + 2
      || buf[0] !== SOCKS_VERSION
      || buf[2] !== 0x00
  ) {
    throw new SocksError("Invalid ConnResp buffer");
  }

  const status = buf[1];
  const [bndAddr, bndPort] = decodeSocksAddrPort(buf, 3);

  return {
    status,
    bndAddr,
    bndPort
  };
}


// UDP request with header

export type UdpReq = {
  frag: number,
  dstAddr: SocksAddr,
  dstPort: number,
  data: Buffer
}

export function encodeUdpReq({ frag, dstAddr, dstPort, data }: UdpReq): Buffer {
  if (!isValidUInt(frag, 0xff)) {
    throw new SocksError("Invalid UdpReq buffer");
  }
  return Buffer.concat([
    Buffer.from([
      0x00,
      0x00,
      frag
    ]),
    encodeSocksAddr(dstAddr),
    encodePort(dstPort),
    data
  ])
}

export function decodeUdpReq(buf: Buffer): UdpReq {
  if (
    buf.length < 3 + 2 + 2
    || buf[0] !== 0x00
    || buf[1] !== 0x00
  ) {
    throw new SocksError("Invalid UdpReq");
  }

  const frag = buf[2];
  const [dstAddr, dstPort] = decodeSocksAddrPort(buf, 3);
  const dstAddrSize = sizeofSocksAddr(dstAddr);
  const data = buf.subarray(3 + dstAddrSize + 2);

  return {
    frag,
    dstAddr,
    dstPort,
    data
  };
}
