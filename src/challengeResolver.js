import pbkdf2Hmac from 'pbkdf2-hmac';
import config from 'config';
export async function resolve(challenge, password) {


    const challengeSplit = challenge.split("$")

    const prefix = challengeSplit[0];
    const iter1 = parseInt(challengeSplit[1]);
    const salt1 = challengeSplit[2];
    const iter2 = parseInt(challengeSplit[3]);
    const salt2 = challengeSplit[4];

    console.log(challengeSplit);

    const hash1 = await pbkdf2Hmac(password, parseHexSaltToIntArray(salt1), iter1, 32, 'SHA-256').then((hash) => {
        return hash
    }, (error) => {
        console.log("error");
        console.log(error);
    }
    );
    console.log("logging hash1: \n" + buf2hex(hash1));

    const hash2 = await pbkdf2Hmac(hash1, parseHexSaltToIntArray(salt2), iter2, 32, 'SHA-256').then((hash) => {
        return hash
    }, (error) => {
        console.log("error");
        console.log(error);
        return "";
    }
    );

    // console.log(one)

    const response = salt2 + "$" + buf2hex(hash2);
    console.log("logging response: \n" + response)
}

function buf2hex(buffer) { // buffer is an ArrayBuffer
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}

function parseHexSaltToIntArray(r) {
    if (r.length % 2 != 0) throw new Error('String has an invalid length for a hex string');
    for (var t = [], n = 0; n < r.length; n += 2) {
        var e = void 0;
        try {
            e = parseInt(r.substr(n, 2), 16)
        } catch (r) {
            throw new Error('Invalid hex string')
        }
        t.push(e)
    }
    return new Uint8Array(t)
}