import { CryoClientWebsocketSession } from "./CryoClientWebsocketSession/CryoClientWebsocketSession.js";
/**
 * Create a Cryo server and attach it to an Express.js app
 * @param host - The host to connect to
 * @param bearer - The bearer token to authenticate with at the server
 * @param use_cale - If cALE (application layer encryption) should be enabled
 * @param timeout - How long to wait until disconnecting
 * */
export async function cryo(host, bearer, use_cale = true, timeout = 5000) {
    return CryoClientWebsocketSession.Connect(host, bearer, use_cale, timeout);
}
