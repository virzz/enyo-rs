use clap::Parser;
use enyo::App;

#[tokio::main]
async fn main() {
    match App::try_parse() {
        Ok(app) => app.run().await,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
}
