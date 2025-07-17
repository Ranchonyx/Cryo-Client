class GuardError extends Error {
	constructor(pMessage: string) {
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
	public static AgainstNull<T>(param: T, message?: string): asserts param is Exclude<T, null> {
		if (param === null)
			throw new GuardError(message ? message : `Assertion failed, "param" (${param}) was null!`);
	}

	//Wenn "param" === "undefined", throw with "message"
	public static AgainstUndefined<T>(param: T, message?: string): asserts param is Exclude<T, undefined> {
		if (param === undefined)
			throw new GuardError(message ? message : `Assertion failed, "param" (${param}) was undefined!`);
	}

	//Wenn "param" === "null" or "param" === "undefined", throw with "message"
	public static AgainstNullish<T>(param: T, message?: string): asserts param is Exclude<Exclude<T, null>, undefined> {
		Guard.AgainstUndefined(param, message);
		Guard.AgainstNull(param, message);
	}

	//Typ von "param" als Typ "T" interpretieren
	public static CastAs<T>(param: unknown): asserts param is T {
		Guard.AgainstNullish(param);
	}

	//Typ von "param" als Typ "T" interpretieren und "param" und "expr" gegen "null" und "undefined" guarden
	public static CastAssert<T>(param: unknown, expr: boolean, message?: string): asserts param is T {
		Guard.AgainstNullish(param, message);
		Guard.AgainstNullish(expr, message);
		if(!expr)
			throw new GuardError(`Parameter assertion failed in CastAssert!`);
	}
}