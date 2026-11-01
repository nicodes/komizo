fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let context = komizo::runtime::signal_context();
    std::process::exit(komizo::caller::command::run(
        &args,
        &context,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    ));
}
