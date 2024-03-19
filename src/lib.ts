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
export function decodeAuthReq(data: Buffer): AuthReq | undefined {
  if (
    data.length < 3
      || data[0] !== SOCKS_VERSION
      || data[1] === 0
      || data.length !== data[1] + 2
  ) {
    return undefined;
  }
  return { methods: [...data.subarray(2)] };
}

export type AuthResp = {
  method: number;
}
export function encodeAuthResp({ method }: AuthResp) {
  return Buffer.from([SOCKS_VERSION, method]);
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

export function decodeSocksAddr(data: Buffer): SocksAddr | undefined {
  if (data.length < 2) {
    return undefined;
  }
  const type = data[0];
  let addr: string;
  switch (type) {
    case SocksAddrType.IPv4:
      if (data.length !== 5) {
        return undefined;
      }
      addr = ip.toString(data, 1);
      break;
    case SocksAddrType.IPv6:
      if (data.length !== 17) {
        return undefined;
      }
      addr = ip.toString(data, 1);
      break;
    case SocksAddrType.Domain:
      const len = data[1];
      if (len + 2 !== data.length) {
        return undefined;
      }
      addr = data.subarray(2).toString();
      break;
    default:
      return undefined;
  }
  return { type, addr };
}
export function encodeSocksAddr({ type, addr }: SocksAddr) {
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
      throw new Error(`Invalid SocksAddrType: ${type}`);
  }
  return Buffer.concat([
    Buffer.from([type]),
    addrBuf
  ]);
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
export function decodeConnReq(data: Buffer): ConnReq | undefined {
  if (
    data.length < 5 + 2
      || data[0] !== SOCKS_VERSION
      || !(data[1] in ConnCmd)
      || data[2] !== 0x00
  ) {
    return undefined;
  }

  const cmd = data[1];
  const dstAddr = decodeSocksAddr(data.subarray(3, data.length - 2));
  if (!dstAddr) {
    return undefined;
  }
  const dstPort = data.readInt16BE(data.length - 2);

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
export function encodeConnResp(resp: ConnResp) {
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
