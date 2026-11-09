fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args
        .first()
        .is_some_and(|value| matches!(value.as_str(), "-h" | "--help" | "help"))
    {
        print!("{}", komizo::deployment::daemon::USAGE);
        return;
    }
    if let Err(error) =
        komizo::deployment::daemon::run(&args, &mut std::io::stdin(), &mut std::io::stdout())
    {
        eprintln!("komizo-box: {error}");
        std::process::exit(1);
    }
}
