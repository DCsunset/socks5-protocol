import { expect, test } from "vitest";
import { ConnCmd, ConnReq, decodeConnReq, decodeSocksAddr, decodeSocksAddrPort, encodeConnReq, encodeSocksAddr, newSocksAddr } from "../src/lib";

test("SocksAddr", () => {
  const addr = newSocksAddr("example.com");
  const buf = encodeSocksAddr(addr);

  expect(decodeSocksAddr(buf)).toEqual(addr);
});


test("ConnReq", () => {
  const addr = newSocksAddr("example.com");
  const req: ConnReq = {
    cmd: ConnCmd.TCP_CONNECT,
    dstAddr: addr,
    dstPort: 10000
  };
  const buf = encodeConnReq(req);

  expect(decodeSocksAddr(buf, 3)).toEqual(addr);
  expect(decodeSocksAddrPort(buf, 3)).toEqual([addr, 10000]);
  expect(decodeConnReq(buf)).toEqual(req);
});

