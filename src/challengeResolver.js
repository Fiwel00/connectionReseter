import crypto from 'crypto';
export async function resolve(challenge, password) {

    const challengeSplit = challenge.split("$")

    const iter1 = parseInt(challengeSplit[1]);
    const salt1 = parseHexToIntArray(challengeSplit[2]);
    const iter2 = parseInt(challengeSplit[3]);
    const salt2 = parseHexToIntArray(challengeSplit[4]);

    console.log(challengeSplit);
    try {
        let hash1 = crypto.pbkdf2Sync(password, salt1, iter1, 32, "sha256");
        let hash2 = crypto.pbkdf2Sync(hash1, salt2, iter2, 32, "sha256");
        return `${salt2}$${hash2.toString("hex").trim()}`;
    } catch (exception) {
        throw new Error(`Encrypting password failed: ${exception.message}`)
    }
}

function parseHexToIntArray(hexNumber) {
    if (hexNumber.length % 2 != 0) throw new Error("String has an invalid length for a hex string");
    let intArray = [];
    for (let iIndex = 0; iIndex < hexNumber.length; iIndex += 2) {
        try {
            intArray.push(parseInt(hexNumber.substr(iIndex, 2), 16));
        } catch (exception) {
            throw new Error("Invalid hex string")
        }
    }
    return new Uint8Array(intArray)
}


