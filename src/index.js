import axios from 'axios';
import crypto from 'crypto-js';
import { XMLParser } from 'fast-xml-parser';
import {resolve} from './ReverseEngineer.js';
import fritz from 'fritzbox.js';

import config from 'config';
const FRITZ_BOX_URL = "http://" + config.get('fritzbox.host');
const parser = new XMLParser();

async function main() {
  const username = config.get('fritzbox.authentication.user');
  const password = config.get('fritzbox.authentication.password');
  const ain = ""
  const loginUrl = FRITZ_BOX_URL + '/login_sid.lua';
  const deviceName = 'placeholder';


  const options = {
    username: username,
    password: password,
    server: config.get('fritzbox.host'),
    protocol: 'https' };

  
    const calls = await fritz.getCalls(options);
    if (calls.error) return console.log('Error: ' + calls.error.message);
    console.log('Got ' + calls.length + 'calls.');
  
  // Step 1: Authenticate and retrieve session ID
  // const sid = await getSessionId(username, password, loginUrl);

  
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
  
  const root = parser.parse(xmlData);
  const sidNode = root.SessionInfo.SID;

  if (sidNode == 0) {
    const challenge = root.SessionInfo.Challenge;

    resolve();

    const challengeResponse = crypto.MD5(`${challenge}-${password}`).toString();
    const challengeUrl = `${loginUrl}?username=${username}&response=${challengeResponse}`;

    const response = await client.get(challengeUrl);
    const xmlData = response.data;
    const newRoot = parser.parse(xmlData);
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
  const root = parser.parse(xmlData);

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