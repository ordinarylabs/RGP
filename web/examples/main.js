import init, { generate_fingerprint, generate_dh_keys, encrypt_dh, decrypt_dh, } from "../pkg/rgp_web.js";


(async () => {
    await init();

    const fingerprint = generate_fingerprint();

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