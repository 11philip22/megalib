use std::env;
use std::process;

pub fn usage_and_exit(usage: &str) -> ! {
    eprintln!("{usage}");
    process::exit(1);
}

pub struct ArgParser {
    args: Vec<String>,
    usage: &'static str,
}

impl ArgParser {
    pub fn new(usage: &'static str) -> Self {
        let args: Vec<String> = env::args().skip(1).collect();

        if args.iter().any(|a| a == "--help" || a == "-h") {
            println!("{usage}");
            process::exit(0);
        }

        Self { args, usage }
    }

    pub fn take_value(&mut self, names: &[&str]) -> Option<String> {
        let mut i = 0;
        while i < self.args.len() {
            if names.contains(&self.args[i].as_str()) {
                let value = self.args.get(i + 1).cloned();
                if value.is_none() {
                    usage_and_exit(self.usage);
                }
                self.args.drain(i..=i + 1);
                return value;
            }
            i += 1;
        }
        None
    }

    pub fn remaining(self) -> Vec<String> {
        self.args
    }
}

#[allow(dead_code)] // Some examples only need ArgParser/usage helpers.
pub struct Credentials {
    pub email: String,
    pub password: String,
    pub proxy: Option<String>,
    pub positionals: Vec<String>,
}

#[allow(dead_code)]
pub fn parse_credentials(usage: &'static str) -> Credentials {
    let mut parser = ArgParser::new(usage);
    let mut credentials = credentials_from_parser(&mut parser, usage);
    credentials.positionals = parser.remaining();
    credentials
}

#[allow(dead_code)]
pub fn credentials_from_parser(parser: &mut ArgParser, usage: &'static str) -> Credentials {
    let email = parser
        .take_value(&["--email", "-e"])
        .unwrap_or_else(|| usage_and_exit(usage));
    let password = parser
        .take_value(&["--password", "-p"])
        .unwrap_or_else(|| usage_and_exit(usage));
    let proxy = parser.take_value(&["--proxy"]);

    Credentials {
        email,
        password,
        proxy,
        positionals: Vec::new(),
    }
}

impl Credentials {
    #[allow(dead_code)]
    pub async fn login(&self) -> megalib::error::Result<megalib::Session> {
        if let Some(proxy) = &self.proxy {
            megalib::Session::login_with_proxy(&self.email, &self.password, proxy).await
        } else {
            megalib::Session::login(&self.email, &self.password).await
        }
    }
}
