use std;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use chrono;

quick_error! {
    #[derive(Debug)]
    pub enum ParseError {
        Io(err: std::io::Error) {
            from()
            description(err.description())
            cause(err)
        }
        Utf8(err: Utf8Error) {
            from()
            description(err.description())
            cause(err)
        }
        FromUtf8(err: FromUtf8Error) {
            from()
            description(err.description())
            cause(err)
        }
        Chrono(err: chrono::ParseError) {
            from()
            description(err.description())
            cause(err)
        }
        WrongType(descr: &'static str) {
            description(descr)
            display("Wrong Type {}", descr)
        }
        InvalidPacket(descr: &'static str) {
            description(descr)
            display("Invalid Packet {}", descr)
        }
        Other(err: Box<std::error::Error>) {
            cause(&**err)
            description(err.description())
            display("Error {}", err.description())
        }
    }
}
