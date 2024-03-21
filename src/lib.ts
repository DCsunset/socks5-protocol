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

import ip from "ip";

const SOCKS_VERSION = 0x05;

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
export function decodeAuthReq(data: Buffer): AuthReq {
  if (
    data.length < 3
      || data[0] !== SOCKS_VERSION
      || data.length !== data[1] + 2
  ) {
    throw new SocksError("Invalid AuthReq");
  }
  return { methods: [...data.subarray(2)] };
}

export type AuthResp = {
  method: number;
}
export function encodeAuthResp({ method }: AuthResp): Buffer {
  return Buffer.from([SOCKS_VERSION, method]);
}
export function decodeAuthResp(data: Buffer): AuthResp {
  if (
    data.length !== 2
      || data[0] !== SOCKS_VERSION
  ) {
    throw new SocksError("Invalid AuthResp");
  }
  return { method: data[1] };
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
      throw new SocksError(`Invalid SocksAddrType: ${type}`);
  }
  return Buffer.concat([
    Buffer.from([type]),
    addrBuf
  ]);
}
export function decodeSocksAddr(data: Buffer): SocksAddr {
  if (data.length < 2) {
    throw new SocksError("Invalid length for SocksAddr");
  }
  const type = data[0];
  let addr: string;
  switch (type) {
    case SocksAddrType.IPv4:
      if (data.length !== 5) {
        throw new SocksError("Invalid length for SocksAddr");
      }
      addr = ip.toString(data, 1);
      break;
    case SocksAddrType.IPv6:
      if (data.length !== 17) {
        throw new SocksError("Invalid length for SocksAddr");
      }
      addr = ip.toString(data, 1);
      break;
    case SocksAddrType.Domain:
      const len = data[1];
      if (len + 2 !== data.length) {
        throw new SocksError("Invalid length for SocksAddr");
      }
      addr = data.subarray(2).toString();
      break;
    default:
      throw new SocksError(`Invalid type for SocksAddr: ${type}`);
  }
  return { type, addr };
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
  if (
    !(cmd in ConnCmd)
      || dstPort < 0
      || dstPort > 0xffff
  ) {
    throw new SocksError("Invalid ConnReq");
  }
  const dstPortBuf = Buffer.allocUnsafe(2);
  dstPortBuf.writeUInt16BE(dstPort);
  return Buffer.concat([
    Buffer.from([
      SOCKS_VERSION,
      cmd,
      0x00
    ]),
    encodeSocksAddr(dstAddr),
    dstPortBuf
  ]);
}
export function decodeConnReq(data: Buffer): ConnReq {
  if (
    data.length < 5 + 2
      || data[0] !== SOCKS_VERSION
      || !(data[1] in ConnCmd)
      || data[2] !== 0x00
  ) {
    throw new SocksError("Invalid ConnReq");
  }

  const cmd = data[1];
  const dstAddr = decodeSocksAddr(data.subarray(3, data.length - 2));
  const dstPort = data.readUInt16BE(data.length - 2);

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

  const addrBuf = encodeSocksAddr(bndAddr);
  const portBuf = Buffer.allocUnsafe(2);
  portBuf.writeUint16BE(bndPort)
  return Buffer.concat([
    Buffer.from([ SOCKS_VERSION, status, 0x00 ]),
    addrBuf,
    portBuf
  ]);
}
export function decodeConnResp(data: Buffer): ConnResp {
  if (
    data.length < 5 + 2
      || data[0] !== SOCKS_VERSION
      || data[2] !== 0x00
  ) {
    throw new SocksError("Invalid ConnResp");
  }

  const status = data[1];
  const bndAddr = decodeSocksAddr(data.subarray(3, data.length - 2));
  const bndPort = data.readUInt16BE(data.length - 2);

  return {
    status,
    bndAddr,
    bndPort
  };
}
