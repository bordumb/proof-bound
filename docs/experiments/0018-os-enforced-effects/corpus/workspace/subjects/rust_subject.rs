use std::env;
use std::error::Error;
use std::fs;
use std::net::TcpStream;
use std::process::Command;

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 5 {
        return Err("expected mode, input, output, attack path, and port".into());
    }
    let mode = &arguments[0];
    let input = &arguments[1];
    let output = &arguments[2];
    let attack = &arguments[3];
    let port = arguments[4].parse::<u16>()?;

    match mode.as_str() {
        "positive" => {
            let value = fs::read_to_string(input)?;
            let environment = env::var("PB_REGISTERED_VALUE")?;
            fs::write(output, format!("{}|{environment}\n", value.trim()))?;
        }
        "read-undeclared" => fs::write(output, fs::read(attack)?)?,
        "env-undeclared" => fs::write(output, env::var("PB_UNDECLARED_VALUE")?)?,
        "exec-unregistered" => {
            let status = Command::new("/usr/bin/true").status()?;
            if !status.success() {
                return Err("unregistered child failed".into());
            }
            fs::write(output, b"child-executed\n")?;
        }
        "network" => {
            TcpStream::connect(("127.0.0.1", port))?;
            fs::write(output, b"network-observed\n")?;
        }
        "write-reviewed" | "write-escape" => {
            fs::write(attack, b"unauthorized-write\n")?;
        }
        _ => return Err(format!("unknown mode: {mode}").into()),
    }
    Ok(())
}
