use std::str::{self, FromStr, from_utf8};
use std::borrow::Cow;
use directive::{Directive, PIDType, PortType};

named!(parens, delimited!(char!('{'), is_not!("}"), char!('}')));

named!(peer_ip_parser <Directive>, do_parse!(
    char!('{') >>
    char!('c') >>
    char!('}') >>
    char!('a') >>
    (Directive::PeerIP)
));

named!(req_cookie_parser <Directive>, map!(
    map_res!(
        terminated!(parens, char!('C')),
        str::from_utf8
    ), |s| Directive::Cookie(Cow::from(s))
));

named!(env_var_parser <Directive>, map!(
    map_res!(
        terminated!(parens, char!('e')),
        str::from_utf8
    ), |s| Directive::EnvVar(Cow::from(s))
));

named!(req_header_parser <Directive>, map!(
    map_res!(
        terminated!(parens, char!('i')),
        str::from_utf8
    ), |s| Directive::ReqHeader(Cow::from(s))
));

named!(note_parser <Directive>, map!(
    map_res!(
        terminated!(parens, char!('n')),
        str::from_utf8
    ), |s| Directive::Note(Cow::from(s))
));

named!(res_header_parser <Directive>, map!(
    map_res!(
        terminated!(parens, char!('o')),
        str::from_utf8
    ), |s| Directive::ResHeader(Cow::from(s))
));


named!(port_type_parser_c <PortType>, map!(
    tag!("canonical"), |_| PortType::Canonical
));
named!(port_type_parser_l <PortType>, map!(
    tag!("local"), |_| PortType::Local
));
named!(port_type_parser_r <PortType>, map!(
    tag!("remote"), |_| PortType::Remote
));
named!(port_type_parser <PortType>, alt!(
    port_type_parser_c |
    port_type_parser_l |
    port_type_parser_r
));

named!(custom_port_parser <Directive>, do_parse!(
    char!('{') >>
    p: port_type_parser >>
    char!('}') >>
    char!('p') >>
    (Directive::Port(p))
));

named!(pid_type_parser_p <PIDType>, map!(
    tag!("pid"), |_| PIDType::PID
));
named!(pid_type_parser_t <PIDType>, map!(
    tag!("tid"), |_| PIDType::TID
));
named!(pid_type_parser_h <PIDType>, map!(
    tag!("hextid"), |_| PIDType::HexTID
));
named!(pid_type_parser <PIDType>, alt!(
    pid_type_parser_p |
    pid_type_parser_t |
    pid_type_parser_h
));

named!(custom_pid_parser <Directive>, do_parse!(
    char!('{') >>
    p: pid_type_parser >>
    char!('}') >>
    char!('P') >>
    (Directive::PID(p))
));

named!(final_status_parser <Directive>, do_parse!(
    char!('>') >>
    char!('s') >>
    (Directive::FinalStatus)
));

named!(req_trailer_parser <Directive>, map!(
    map_res!(
        terminated!(parens, tag!("^ti")),
        str::from_utf8
    ), |s| Directive::ReqTrailer(Cow::from(s))
));

named!(res_trailer_parser <Directive>, map!(
    map_res!(
        terminated!(parens, tag!("^to")),
        str::from_utf8
    ), |s| Directive::ResTrailer(Cow::from(s))
));

named!(pub directive_parser <Directive>,
    preceded!(char!('%'), alt!(
        peer_ip_parser |
        req_cookie_parser |
        env_var_parser |
        req_header_parser |
        note_parser |
        res_header_parser |
        custom_port_parser |
        custom_pid_parser |
        final_status_parser |
        req_trailer_parser |
        res_trailer_parser |
        map_res!(take_str!(1), Directive::from_str)
    ))
);

named!(constant_parser <Directive>, map!(
    map_res!(
        is_not!("%"),
        from_utf8
    ),
    |s| Directive::Literal(Cow::from(s))
));

named!(pub logformat_parser <Vec<Directive>>,
    many0!(
        alt!(
            directive_parser |
            constant_parser
        )
    )
);


#[cfg(test)]
mod tests {
    use super::*;

    use std::borrow::Cow;
    // use test::Bencher;

    use nom::ErrorKind;
    use nom::IResult::{Done, Error, Incomplete};
    use nom::Needed::Size;

    use directive::{Directive, PortType, PIDType};

    #[test]
    fn test_parens_parser() {
        assert_eq!(parens(b"{a}"), Done(&b""[..], &b"a"[..]));
    }

    #[test]
    fn test_parens_parser_fail() {
        assert_eq!(parens(b"{abc"), Incomplete(Size(5)));
    }

    #[test]
    fn test_port_type_parser() {
        assert_eq!(port_type_parser_c(b"canonical"), Done(&b""[..], PortType::Canonical));
    }

    #[test]
    fn test_port_type_parser_fail() {
        assert_eq!(port_type_parser(b"blah"), Error(ErrorKind::Alt));
    }

    macro_rules! assert_directive(
        ($format:expr, $dir:expr) => {
            assert_eq!(directive_parser($format), Done(&b""[..], $dir));
        }
    );

    #[test]
    fn test_directive_parser() {
        assert_directive!(b"%a", Directive::ClientIP);
    }

    #[test]
    fn test_directive_parser_percent() {
        assert_directive!(b"%%", Directive::Literal(Cow::from("%")));
    }
    #[test]
    fn test_directive_parser_client_ip() {
        assert_directive!(b"%a", Directive::ClientIP);
    }
    #[test]
    fn test_directive_parser_underlying_ip() {
        assert_directive!(b"%{c}a", Directive::PeerIP);
    }
    #[test]
    fn test_directive_parser_local_ip() {
        assert_directive!(b"%A", Directive::LocalIP);
    }
    #[test]
    fn test_directive_parser_res_size_excluding_headers() {
        assert_directive!(b"%B", Directive::ResSizeExcludingHeaders);
    }
    #[test]
    fn test_directive_parser_res_size() {
        assert_directive!(b"%b", Directive::ResSize);
    }
    #[test]
    fn test_directive_parser_req_cookie() {
        assert_directive!(b"%{FOO}C", Directive::Cookie(Cow::from("FOO")));
    }
    #[test]
    fn test_directive_parser_request_time() {
        assert_directive!(b"%D", Directive::ReqTime);
    }
    #[test]
    fn test_directive_parser_env_var() {
        assert_directive!(b"%{BAR}e", Directive::EnvVar(Cow::from("BAR")));
    }
    #[test]
    fn test_directive_parser_filename() {
        assert_directive!(b"%f", Directive::Filename);
    }
    #[test]
    fn test_directive_parser_hostname() {
        assert_directive!(b"%h", Directive::Hostname);
    }
    #[test]
    fn test_directive_parser_protocol() {
        assert_directive!(b"%H", Directive::Protocol);
    }
    #[test]
    fn test_directive_parser_req_header() {
        assert_directive!(b"%{BAZ}i", Directive::ReqHeader(Cow::from("BAZ")));
    }
    #[test]
    fn test_directive_parser_keepalive() {
        assert_directive!(b"%k", Directive::KeepAlive);
    }
    #[test]
    fn test_directive_parser_logname() {
        assert_directive!(b"%l", Directive::Logname);
    }
    #[test]
    fn test_directive_parser_req_id() {
        assert_directive!(b"%L", Directive::ErrID);
    }
    #[test]
    fn test_directive_parser_method() {
        assert_directive!(b"%m", Directive::Method);
    }
    #[test]
    fn test_directive_parser_module_note() {
        assert_directive!(b"%{QUX}n", Directive::Note(Cow::from("QUX")));
    }
    #[test]
    fn test_directive_parser_res_header() {
        assert_directive!(b"%{QUUX}o", Directive::ResHeader(Cow::from("QUUX")));
    }
    #[test]
    fn test_directive_parser_canonical_port() {
        assert_directive!(b"%p", Directive::Port(PortType::Canonical));
    }
    #[test]
    fn test_directive_parser_custom_port() {
        assert_directive!(b"%{canonical}p", Directive::Port(PortType::Canonical));
        assert_directive!(b"%{local}p", Directive::Port(PortType::Local));
        assert_directive!(b"%{remote}p", Directive::Port(PortType::Remote));
        assert_eq!(directive_parser(b"%{quuz}p"), Error(ErrorKind::Alt));
    }
    #[test]
    fn test_directive_parser_pid() {
        assert_directive!(b"%P", Directive::PID(PIDType::PID));
    }
    #[test]
    fn test_directive_parser_custom_pid() {
        assert_directive!(b"%{pid}P", Directive::PID(PIDType::PID));
        assert_directive!(b"%{tid}P", Directive::PID(PIDType::TID));
        assert_directive!(b"%{hextid}P", Directive::PID(PIDType::HexTID));
        assert_eq!(directive_parser(b"%{corge}P"), Error(ErrorKind::Alt));
    }
    #[test]
    fn test_directive_parser_query() {
        assert_directive!(b"%q", Directive::Query);
    }
    #[test]
    fn test_directive_parser_first_line_of_request() {
        assert_directive!(b"%r", Directive::ReqFirstLine);
    }
    #[test]
    fn test_directive_parser_res_handler() {
        assert_directive!(b"%R", Directive::ResHandler);
    }
    #[test]
    fn test_directive_parser_status() {
        assert_directive!(b"%s", Directive::Status);
    }
    #[test]
    fn test_directive_parser_final_status() {
        assert_directive!(b"%>s", Directive::FinalStatus);
    }
    #[test]
    fn test_directive_parser_req_time_received() {
        assert_directive!(b"%t", Directive::ReqRecvTime);
    }
    #[test]
    #[ignore]
    fn test_directive_parser_custom_time() {
        assert_directive!(b"%{grault}t", Directive::ReqRecvTime);
    }
    #[test]
    fn test_directive_parser_time_to_serve() {
        assert_directive!(b"%T", Directive::ReqServeTime);
    }
    #[test]
    #[ignore]
    fn test_directive_parser_custom_time_to_serve() {
        assert_directive!(b"%{garply}T", Directive::ReqServeTime);
    }
    #[test]
    fn test_directive_parser_user() {
        assert_directive!(b"%u", Directive::User);
    }
    #[test]
    fn test_directive_parser_path() {
        assert_directive!(b"%U", Directive::Path);
    }
    #[test]
    fn test_directive_parser_server_name() {
        assert_directive!(b"%v", Directive::ServerName);
    }
    #[test]
    fn test_directive_parser_canonical_server_name() {
        assert_directive!(b"%V", Directive::CanonicalServerName);
    }
    #[test]
    fn test_directive_parser_status_when_res_complete() {
        assert_directive!(b"%X", Directive::ResStatus);
    }
    #[test]
    fn test_directive_parser_bytes_received() {
        assert_directive!(b"%I", Directive::SizeReceived);
    }
    #[test]
    fn test_directive_parser_bytes_sent() {
        assert_directive!(b"%O", Directive::SizeSent);
    }
    #[test]
    fn test_directive_parser_bytes_transferred() {
        assert_directive!(b"%S", Directive::Size);
    }
    #[test]
    fn test_directive_parser_req_trailer_line() {
        assert_directive!(b"%{waldo}^ti", Directive::ReqTrailer(Cow::from("waldo")));
    }
    #[test]
    fn test_directive_parser_res_trailer_line() {
        assert_directive!(b"%{fred}^to", Directive::ResTrailer(Cow::from("fred")));
    }

    // #[bench]
    // fn bench_directive_parser(b: &mut Bencher) {
    //     b.iter(|| directive_parser(b"%S"));
    // }

    #[test]
    fn test_logformat_parser_single() {
        assert_eq!(logformat_parser(b"%a"), Done(&b""[..], vec![Directive::ClientIP]));
    }

    #[test]
    fn test_logformat_parser_multiple() {
        assert_eq!(logformat_parser(b"%a%a%a%a%a%a"),
                   Done(&b""[..], vec![Directive::ClientIP,
                                       Directive::ClientIP,
                                       Directive::ClientIP,
                                       Directive::ClientIP,
                                       Directive::ClientIP,
                                       Directive::ClientIP]));
    }

    #[test]
    fn test_logformat_parser_multiple_spaces() {
        assert_eq!(logformat_parser(b"%a %a %a %a %a %a"),
                   Done(&b""[..], vec![Directive::ClientIP,
                                       Directive::Literal(Cow::from(" ")),
                                       Directive::ClientIP,
                                       Directive::Literal(Cow::from(" ")),
                                       Directive::ClientIP,
                                       Directive::Literal(Cow::from(" ")),
                                       Directive::ClientIP,
                                       Directive::Literal(Cow::from(" ")),
                                       Directive::ClientIP,
                                       Directive::Literal(Cow::from(" ")),
                                       Directive::ClientIP]));
    }
}
