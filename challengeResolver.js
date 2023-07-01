import pbkdf2Hmac from 'pbkdf2-hmac'
export async function resolve() {
    
    
    const challenge = "2$60000$9f69e17a0b4931b3798e79b786bece16$6000$c4ecf7566a26c72de392eb8fab98903b"
    const challengeSplit = challenge.split("$")
    
    const password = "";
    
    const prefix =challengeSplit[0];
    const iter1 = parseInt(challengeSplit[1]);
    const salt1 = challengeSplit[2];
    const iter2 = challengeSplit[3];
    const salt2 = challengeSplit[4];
    
    console.log(challengeSplit);
    
    const hash1 =  await pbkdf2Hmac(password, salt1, iter1, 32).then((response) => {
        return response
    }, (error) => {
        console.log("error");
        console.log(error);
    }
    );
    console.log(hash1);
    
    // console.log(one)
    
    const response2 = ""
    console.log(response2)
}