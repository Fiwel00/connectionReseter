import axios from 'axios';
import crypto from 'crypto-js';
import { XMLParser } from 'fast-xml-parser';
import {resolve} from './challengeResolver.js';
const FRITZ_BOX_URL = ""


async function main() {
  const username = '';
  const password = '';
  const ain = ""
  const loginUrl = FRITZ_BOX_URL + '/login_sid.lua';
  const deviceName = 'placeholder';

  // Step 1: Authenticate and retrieve session ID
  const sid = await getSessionId(username, password, loginUrl);

  
  // Step 2: Get list of connected devices and find the device with the specified name
  // const device = await getDeviceByName(sid, deviceName);

  // Step 3: Reset connection properties of the device
  // await resetConnectionProperties(sid, device);

  // console.log('Connection properties reset successful.');
}

async function getSessionId(username, password, loginUrl){
  let client = axios.create();
  const response = await client.get(loginUrl);
  const xmlData = response.data;
  const parser = new XMLParser();
  const root = parser.parse(xmlData, { ignoreAttributes: false, parseAttributeValue: true });
  const sidNode = root.SessionInfo.SID;

  if (sidNode == 0) {
    const challenge = root.SessionInfo.Challenge;



    resolve();



    const challengeResponse = crypto.MD5(`${challenge}-${password}`).toString();
    const challengeUrl = `${loginUrl}?username=${username}&response=${challengeResponse}`;

    const response = await client.get(challengeUrl);
    const xmlData = response.data;
    const newRoot = parser.parse(xmlData, { ignoreAttributes: false, parseAttributeValue: true });
    const sid = newRoot.SessionInfo.SID;
    console.log(JSON.stringify(newRoot))

    console.log(`Session ID: ${sid}`);
    return sid;
  } else {
    console.log(`Session ID: ${sidNode}`);
    return sidNode;
  }
}

async function getDeviceByName(sid, deviceName) {
  const client = axios.create();
  const url = `${FRITZ_BOX_URL}/webservices/homeautoswitch.lua?ain=1234567890&sid=${sid}`;
  const response = await client.get(url, {
    headers: { Cookie: `sid=${sid}` },
  });
  const xmlData = response.data;
  const root = parse(xmlData, { ignoreAttributes: false, parseAttributeValue: true });

  for (const deviceNode of root.children) {
    if (deviceNode.device_name === deviceName) {
      console.log(`Device found: ${deviceName}`);
      return deviceNode;
    }
  }

  throw new Error('Device with specified name not found');
}

async function resetConnectionProperties(sid, device) {
  const client = axios.create();
  const url = `${FRITZ_BOX_URL}/webservices/homeautoswitch.lua?ain=${device}&switchcmd=setswitchonoff&switchcmd&devicelock=false&oldlock`;
  await client.get(url, {
    headers: { Cookie: `sid=${sid}` },
  });
}

main().catch((error) => console.error(error));