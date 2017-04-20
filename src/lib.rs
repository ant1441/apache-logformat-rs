// #![feature(test)]
// extern crate test;

#[macro_use]
extern crate nom;

mod directive;
mod parser;

// Predefined log formats
pub const CLF: &'static str = "%h %l %u %t \"%r\" %>s %b";
pub use parser::logformat_parser;
pub use directive::Directive;

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use nom::IResult::{Done};
    use super::{CLF, Directive, logformat_parser};

    #[test]
    fn test_logformat_parser_() {
        assert_eq!(logformat_parser(CLF.as_bytes()),
                   Done(&b""[..],
                        vec![Directive::Hostname,
                             Directive::Literal(Cow::from(" ")),
                             Directive::Logname,
                             Directive::Literal(Cow::from(" ")),
                             Directive::User,
                             Directive::Literal(Cow::from(" ")),
                             Directive::ReqRecvTime,
                             Directive::Literal(Cow::from(" \"")),
                             Directive::ReqFirstLine,
                             Directive::Literal(Cow::from("\" ")),
                             Directive::FinalStatus,
                             Directive::Literal(Cow::from(" ")),
                             Directive::ResSize,
                        ]
                     ));
    }
}
