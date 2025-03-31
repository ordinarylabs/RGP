# RGP Web

WebAssembly bindings for [RGP](https://github.com/ordinarylabs/RGP).

## Usage

```js
import init, { generate_fingerprint, generate_dh_keys, encrypt_dh, decrypt_dh, } from "https://unpkg.com/rgp-web@0.2.0/rgp_web.js";


(async () => {
    await init();

    // fingerprint of sender
    const fingerprint = generate_fingerprint();

    // public/private keys for sender/receiver
    const senderKeys = generate_dh_keys();
    const receiverKeys = generate_dh_keys();

    // content to be sent
    const encoder = new TextEncoder();
    const content = encoder.encode("hello world :)");

    // encrypt
    const encryptedContent = encrypt_dh(
        fingerprint.fingerprint,
        content,
        senderKeys.private,
        receiverKeys.public,
    );
    console.log("encrypted: ", encryptedContent);

    // decrypt
    const decryptedContent = decrypt_dh(
        0,
        encryptedContent,
        fingerprint.verifier,
        senderKeys.public,
        receiverKeys.private
    );

    const decoder = new TextDecoder();
    console.log("decrypted: ", decoder.decode(decryptedContent));
})();
```

## Development

Install [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/).

```sh
cargo install wasm-pack
```

Build with wasm-pack.

```sh
wasm-pack build --target web
```

Publish with wasm-pack.

```sh
wasm-pack publish
```
