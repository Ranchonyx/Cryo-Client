import {CryoClientWebsocketSession} from "./CryoClientWebsocketSession/CryoClientWebsocketSession.js";

/**
 * Create a Cryo server and attach it to an Express.js app
 * @param host - The host to connect to
 * @param bearer - The bearer token to authenticate with at the server
 * @param timeout - How long to wait until disconnecting
 * */
export async function cryo(host: string, bearer: string, timeout: number = 5000) {
    return CryoClientWebsocketSession.Connect(host, bearer, timeout)
}