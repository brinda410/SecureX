import {
    generateAESKey,
    encryptMessage,
    decryptMessage
} from "../src/utils/crypto.js";

async function runTests() {
    let passed = 0;

    const check = (name, condition) => {
        console.log(`${condition ? "PASS" : "FAIL"}: ${name}`);
        if (condition) passed++;
    };

    const key = await generateAESKey();
    const original = "SECUREX_TAMPERING_TEST_2026";

    const encrypted = await encryptMessage(original, key);

    // Test 1: Normal decryption
    const decrypted = await decryptMessage(
        encrypted.ciphertext,
        encrypted.iv,
        key
    );

    check("Normal encryption and decryption", decrypted === original);

    // Test 2: Modified ciphertext
    const cipherBytes = Uint8Array.from(
        atob(encrypted.ciphertext),
        c => c.charCodeAt(0)
    );

    cipherBytes[0] ^= 1;

    const tamperedCiphertext = btoa(
        String.fromCharCode(...cipherBytes)
    );

    let ciphertextRejected = false;

    try {
        await decryptMessage(tamperedCiphertext, encrypted.iv, key);
    } catch {
        ciphertextRejected = true;
    }

    check("Tampered ciphertext rejected", ciphertextRejected);

    // Test 3: Modified IV
    const ivBytes = Uint8Array.from(
        atob(encrypted.iv),
        c => c.charCodeAt(0)
    );

    ivBytes[0] ^= 1;

    const tamperedIV = btoa(
        String.fromCharCode(...ivBytes)
    );

    let ivRejected = false;

    try {
        await decryptMessage(encrypted.ciphertext, tamperedIV, key);
    } catch {
        ivRejected = true;
    }

    check("Tampered IV rejected", ivRejected);

    console.log(`RESULT: ${passed}/3 tests passed.`);
}

runTests().catch(console.error);