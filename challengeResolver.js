import pbkdf2Hmac from 'pbkdf2-hmac';
import config from 'config';
export async function resolve() {
    
    
    const challenge = "2$10000$5A1711$2000$5A1722"
    const challengeSplit = challenge.split("$")
    
    const password = "1exmaple!"//config.get('fritzbox.authentication.password');
    const prefix = challengeSplit[0];
    const iter1 = parseInt(challengeSplit[1]);
    const salt1 = challengeSplit[2];
    const iter2 = parseInt(challengeSplit[3]);
    const salt2 = challengeSplit[4];
    
    console.log(challengeSplit);
    
    const hash1 =  await pbkdf2Hmac(password, salt1, iter1, 32,'SHA-256').then((hash) => {
        return hash
    }, (error) => {
        console.log("error");
        console.log(error);
    }
    );
    console.log("logging hash1: \n" + buf2hex(hash1));

    const hash2 =  await pbkdf2Hmac(hash1, salt2, iter2, 32, 'SHA-256').then((hash) => {
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