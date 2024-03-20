# socks5-protocol

[![NPM Version](https://img.shields.io/npm/v/socks5-protocol)](https://www.npmjs.com/package/socks5-protocol)
[![GitHub License](https://img.shields.io/github/license/DCsunset/socks5-protocol)](https://github.com/DCsunset/socks5-protocol)

A Node.js library (in TypeScript and ESM) to encode/decode messages in SOCKS5 protocol.


## Installation

```
npm i socks5-protocol
```


## TODO

- [ ] Add UDP message
- [ ] Add more functions for client-side use


## Usage

The naming of message types mostly follows the [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928).

Here a list of implemented messages:

- `AuthReq`: The message from client for auth method selection
- `AuthResp`: Server's response to `AuthReq`
- `ConnReq`: The message from client to request a connection, binding, or association
- `ConnResp`: Server's response to `ConnReq`


## License

Apache-2.0

```
Copyright 2024 DCsunset

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
