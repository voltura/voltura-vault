#[path = "../hello.rs"]
mod hello;
fn main() {
    match hello::status() {
        Ok(s) => println!("{}", serde_json::to_string_pretty(&s).unwrap()),
        Err(e) => { eprintln!("{e}"); std::process::exit(1); }
    }
}
