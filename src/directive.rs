use std::borrow::Cow;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub enum PortType {
    Canonical,
    Local,
    Remote,
}

#[derive(Debug, PartialEq)]
pub enum PIDType {
    PID,
    TID,
    HexTID,
}

#[derive(Debug, PartialEq)]
pub enum Directive<'a> {
    /// Literal string.
    Literal(Cow<'a, str>),
    /// Client IP address of the request (see the [mod_remoteip](https://httpd.apache.org/docs/trunk/mod/mod_remoteip.html) module).
    ClientIP,
    /// Underlying peer IP address of the connection (see the [mod_remoteip](https://httpd.apache.org/docs/trunk/mod/mod_remoteip.html) module).
    PeerIP,
    /// Local IP-address.
    LocalIP,
    /// Size of response in bytes, excluding HTTP headers.
    ResSizeExcludingHeaders,
    /// Size of response in bytes, excluding HTTP headers. In CLF format, i.e. a '-' rather than a
    /// 0 when no bytes are sent.
    ResSize,
    /// The contents of cookie in the request sent to the server. Only version 0 cookies
    /// are fully supported.
    Cookie(Cow<'a, str>),
    /// The time taken to serve the request, in microseconds.
    ReqTime,
    /// The contents of the environment variable.
    EnvVar(Cow<'a, str>),
    /// Filename.
    Filename,
    /// Remote hostname. Will log the IP address if
    /// [HostnameLookups](https://httpd.apache.org/docs/trunk/mod/core.html#hostnamelookups)
    /// is set to Off, which is the default. If it logs the hostname for only a few hosts,
    /// you probably have access control directives mentioning them by name.
    /// See [the Require host documentation](https://httpd.apache.org/docs/trunk/mod/mod_authz_host.html#reqhost).
    Hostname,
    /// The request protocol.
    Protocol,
    /// The contents of header line(s) in the request sent to the server. Changes made by
    /// other modules (e.g. [mod_headers](https://httpd.apache.org/docs/trunk/mod/mod_headers.html))
    /// affect this. If you're interested in what the request header was prior to when most modules
    /// would have modified it, use
    /// [mod_setenvif](https://httpd.apache.org/docs/trunk/mod/mod_setenvif.html) to copy the header
    /// into an internal environment variable and log that value with the %{VARNAME}e described above.
    ReqHeader(Cow<'a, str>),
    /// Number of keepalive requests handled on this connection. Interesting if [KeepAlive](https://httpd.apache.org/docs/trunk/mod/core.html#keepalive)
    /// is being used, so that, for example, a '1' means the first keepalive request after the initial one,
    /// '2' the second, etc...; otherwise this is always 0 (indicating the initial request).
    KeepAlive,
    /// Remote logname (from identd, if supplied). This will return a dash unless [mod_ident](https://httpd.apache.org/docs/trunk/mod/mod_ident.html)
    /// is present and [IdentityCheck](https://httpd.apache.org/docs/trunk/mod/mod_ident.html#identitycheck) is set On.
    Logname,
    /// The request log ID from the error log (or '-' if nothing has been logged to the error log
    /// for this request). Look for the matching error log line to see what request caused what
    /// error.
    ErrID,
    /// The request method.
    Method,
    /// The contents of note VARNAME from another module.
    Note(Cow<'a, str>),
    /// The contents of header line(s) in the reply.
    ResHeader(Cow<'a, str>),
    // The canonical port of the server serving the request.
    // See Port(Canonical)
    /// The canonical port of the server serving the request, or the server's actual port, or the
    /// client's actual port. Valid formats are canonical, local, or remote.
    Port(PortType),
    // The process ID of the child that serviced the request.
    // See PID(PID)
    PID(PIDType),
    /// The query string (prepended with a ? if a query string exists, otherwise an empty string).
    Query,
    /// First line of request.
    ReqFirstLine,
    /// The handler generating the response (if any).
    ResHandler,
    /// Status. For requests that have been internally redirected, this is the status of the
    /// original request.
    Status,
    /// Use %>s for the final status.
    FinalStatus,
    /// Time the request was received, in the format [18/Sep/2011:19:18:28 -0400]. The last number
    /// indicates the timezone offset from GMT
    ReqRecvTime,
    // [TODO]: Time with format
    /// The time taken to serve the request, in seconds.
    ReqServeTime,
    /// The time taken to serve the request, in a time unit given by UNIT. Valid units are ms for
    /// milliseconds, us for microseconds, and s for seconds. Using s gives the same result as %T
    /// without any format; using us gives the same result as %D. Combining %T with a unit is
    /// available in 2.4.13 and later.
    // [TODO]: Time with unit
    /// Remote user if the request was authenticated. May be bogus if return status (%s) is 401
    /// (unauthorized).
    User,
    /// The URL path requested, not including any query string.
    Path,
    /// The canonical [ServerName](https://httpd.apache.org/docs/trunk/mod/core.html#servername) of the server serving the request.
    ServerName,
    /// The server name according to the [UseCanonicalName](https://httpd.apache.org/docs/trunk/mod/core.html#usecanonicalname) setting.
    CanonicalServerName,
    /// Connection status when response is completed:
    ///
    /// * X = Connection aborted before the response completed.
    /// * + = Connection may be kept alive after the response is sent.
    /// * - = Connection will be closed after the response is sent.
    ResStatus,
    /// Bytes received, including request and headers. Cannot be zero. You need to enable [mod_logio](https://httpd.apache.org/docs/trunk/mod/mod_logio.html)
    /// to use this.
    SizeReceived,
    /// Bytes sent, including headers. May be zero in rare cases such as when a request is aborted
    /// before a response is sent. You need to enable
    /// [mod_logio](https://httpd.apache.org/docs/trunk/mod/mod_logio.html) to use this.
    SizeSent,
    /// Bytes transferred (received and sent), including request and headers, cannot be zero. This
    /// is the combination of %I and %O. You need to enable [mod_logio](https://httpd.apache.org/docs/trunk/mod/mod_logio.html)
    /// to use this.
    Size,
    /// The contents of trailer line(s) in the request sent to the server.
    ReqTrailer(Cow<'a, str>),
    /// The contents of trailer line(s) in the response sent from the server.
    ResTrailer(Cow<'a, str>),
}

impl<'a> FromStr for Directive<'a> {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::Directive::*;
        let d = match s {
            "%" => Literal(Cow::from("%")),
            "a" => ClientIP,
            // {c}a => Underlying IP
            "A" => LocalIP,
            "B" => ResSizeExcludingHeaders,
            "b" => ResSize,
            // %{VARNAME}C => Request Cookie
            "D" => ReqTime,
            // %{VARNAME}e => Environment Variable
            "f" => Filename,
            "h" => Hostname,
            "H" => Protocol,
            // %{VARNAME}i => Request Headers
            "k" => KeepAlive,
            "l" => Logname,
            "L" => ErrID,
            "m" => Method,
            // %{VARNAME}n => Module note
            // %{VARNAME}o => Response Headers
            "p" => Port(PortType::Canonical),
            // %{format}p => Port
            "P" => PID(PIDType::PID),
            // %{format}P => PID/TID
            "q" => Query,
            "r" => ReqFirstLine,
            "R" => ResHandler,
            "s" => Status,
            // %>s => FinalStatus
            "t" => ReqRecvTime,
            // %{format}t => Time with format
            "T" => ReqServeTime,
            // %{UNIT}t => Time with unit
            "u" => User,
            "U" => Path,
            "v" => ServerName,
            "V" => CanonicalServerName,
            "X" => ResStatus,
            "I" => SizeReceived,
            "O" => SizeSent,
            "S" => Size,
            // %{VARNAME}^ti => Request trailer line
            // %{VARNAME}^to => Response trailer line
            _ => return Err("invalid char"),
        };
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directive_from_str() {
        assert_eq!(Directive::ClientIP, Directive::from_str("a").unwrap());
    }

    #[test]
    fn test_directive_from_str_percent() {
        assert_eq!(Directive::Literal(Cow::from("%")),
                   Directive::from_str("%").unwrap());
    }
}
