namespace RudeAuth;

// ErrorCode is the SDK's error vocabulary, one to one with the C++ SDK's Error
// enum. Read it from RudeAuthException.Code.
public enum ErrorCode
{
    Network,          // the server could not be reached
    BadResponse,      // malformed, or the envelope did not decode
    SignatureInvalid, // the responder is not holding your application's key
    NonceMismatch,    // a replayed response
    ClockSkew,        // this machine's clock is too far from the server's
    LicenseInvalid,
    LicenseExpired,
    DeviceLimit,
    DeviceBlacklisted,
    RateLimited,
    SessionExpired,
    EndpointDisabled,
    AppDisabled,
    ResetUnavailable,
    FileNotFound,
    ServerError,
    Internal,
}

// RudeAuthException is thrown for every failure. There is deliberately no method
// returning a bool that means "is licensed": Authenticate returns a Session or
// throws this, and the gating calls exist only on a Session, which cannot be
// constructed without a verified signature.
public sealed class RudeAuthException : Exception
{
    public ErrorCode Code { get; }

    public RudeAuthException(ErrorCode code, string message, Exception? inner = null)
        : base(message, inner)
    {
        Code = code;
    }

    // FromWire maps the server's coarse error codes onto ErrorCode. An
    // unrecognised code becomes ServerError rather than being ignored.
    internal static RudeAuthException FromWire(string code) => code switch
    {
        "LICENSE_INVALID" => new(ErrorCode.LicenseInvalid, "licence invalid"),
        "LICENSE_EXPIRED" => new(ErrorCode.LicenseExpired, "licence expired"),
        "DEVICE_LIMIT" => new(ErrorCode.DeviceLimit, "device limit reached"),
        "DEVICE_BLACKLISTED" => new(ErrorCode.DeviceBlacklisted, "device blacklisted"),
        "RATE_LIMITED" => new(ErrorCode.RateLimited, "rate limited"),
        "SESSION_EXPIRED" => new(ErrorCode.SessionExpired, "session expired"),
        "ENDPOINT_DISABLED" => new(ErrorCode.EndpointDisabled, "endpoint disabled"),
        "APP_DISABLED" => new(ErrorCode.AppDisabled, "application unavailable"),
        "CLOCK_SKEW" => new(ErrorCode.ClockSkew, "clock skew"),
        "RESET_UNAVAILABLE" => new(ErrorCode.ResetUnavailable, "device reset unavailable"),
        "FILE_NOT_FOUND" => new(ErrorCode.FileNotFound, "no such file for this application"),
        _ => new(ErrorCode.ServerError, "server error"),
    };
}
