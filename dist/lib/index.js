import { CryoClientWebsocketSession } from "./CryoClientWebsocketSession/CryoClientWebsocketSession.js";
/**
 * Create a Cryo server and attach it to an Express.js app
 * @param pApp - The express app to attach the server to
 * @param pTokenValidator - An implementation of the {@link ITokenValidator} interface to validate incoming websocket connections
 * @param options - Optional arguments, {@link CryoWebsocketServerOptions}
 * */
export async function cryo(host, bearer, timeout = 5000) {
    return CryoClientWebsocketSession.Connect(host, bearer, timeout);
}
