fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        print!("{}", komizo::deployment::operator::USAGE);
        return;
    }
    if let Err(error) = komizo::deployment::operator::run(&args, &mut std::io::stdout()) {
        eprintln!("komizo: {error}");
        std::process::exit(1);
    }
}
