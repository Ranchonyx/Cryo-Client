class GuardError extends Error {
    constructor(pMessage) {
        super(pMessage);
        Error.captureStackTrace ||= () => {
        };
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, GuardError);
        }
        Object.setPrototypeOf(this, GuardError.prototype);
    }
}
/*
* Helferklasse mit statischen Funktionen zum "undefined" und "null"-checken, im Wesentlichen fancy asserts und casts.
* */
export default class Guard {
    //wenn "param" === null, throw with "message"
    static AgainstNull(param, message) {
        if (param === null)
            throw new GuardError(message ? message : `Assertion failed, "param" (${param}) was null!`);
    }
    //Wenn "param" === "undefined", throw with "message"
    static AgainstUndefined(param, message) {
        if (param === undefined)
            throw new GuardError(message ? message : `Assertion failed, "param" (${param}) was undefined!`);
    }
    //Wenn "param" === "null" or "param" === "undefined", throw with "message"
    static AgainstNullish(param, message) {
        Guard.AgainstUndefined(param, message);
        Guard.AgainstNull(param, message);
    }
    //Typ von "param" als Typ "T" interpretieren
    static CastAs(param) {
        Guard.AgainstNullish(param);
    }
    //Typ von "param" als Typ "T" interpretieren und "param" und "expr" gegen "null" und "undefined" guarden
    static CastAssert(param, expr, message) {
        Guard.AgainstNullish(param, message);
        Guard.AgainstNullish(expr, message);
        if (!expr)
            throw new GuardError(`Parameter assertion failed in CastAssert!`);
    }
}
