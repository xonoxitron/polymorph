use std::env;
use std::fs;
use std::process;
use std::time::Instant;

mod detectors;
mod scanner;
mod report;
mod utils;

use scanner::Scanner;
use report::{OutputFormat, ReportGenerator};

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct Config {
    file_path: String,
    output_format: OutputFormat,
    verbose: bool,
    quiet: bool,
    show_offsets: bool,
}

impl Config {
    fn from_args(args: Vec<String>) -> Result<Config, String> {
        if args.len() < 2 {
            return Err("Missing required argument".to_string());
        }

        let mut file_path = String::new();
        let mut output_format = OutputFormat::Human;
        let mut verbose = false;
        let mut quiet = false;
        let mut show_offsets = false;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-h" | "--help" => return Err("help".to_string()),
                "-v" | "--verbose" => verbose = true,
                "-q" | "--quiet" => quiet = true,
                "-j" | "--json" => output_format = OutputFormat::Json,
                "-o" | "--offsets" => show_offsets = true,
                "-V" | "--version" => {
                    println!("PolyMorph v{}", VERSION);
                    process::exit(0);
                }
                arg if arg.starts_with('-') => {
                    return Err(format!("Unknown option: {}", arg));
                }
                _ => {
                    if file_path.is_empty() {
                        file_path = args[i].clone();
                    }
                }
            }
            i += 1;
        }

        if file_path.is_empty() {
            return Err("No file specified".to_string());
        }

        Ok(Config {
            file_path,
            output_format,
            verbose,
            quiet,
            show_offsets,
        })
    }
}

fn print_help() {
    println!("PolyMorph v{} - Polyglot Malware Detection", VERSION);
    println!("\nUSAGE:");
    println!("    polymorph [OPTIONS] <FILE>");
    println!("\nOPTIONS:");
    println!("    -h, --help       Show this help");
    println!("    -v, --verbose    Verbose output");
    println!("    -q, --quiet      Minimal output");
    println!("    -j, --json       JSON output");
    println!("    -o, --offsets    Show offsets");
    println!("    -V, --version    Show version");
    println!("\nEXIT CODES:");
    println!("    0 - Clean, 1 - Low, 2 - Medium, 3 - High, 4 - Critical, 5 - Error");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let config = match Config::from_args(args) {
        Ok(cfg) => cfg,
        Err(e) => {
            if e == "help" {
                print_help();
                process::exit(0);
            }
            eprintln!("Error: {}", e);
            process::exit(5);
        }
    };

    let binary_data = match fs::read(&config.file_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            process::exit(5);
        }
    };

    if !config.quiet && config.output_format != OutputFormat::Json {
        println!("Analyzing: {}", config.file_path);
        println!("Size: {}", utils::format_bytes(binary_data.len()));
    }

    let start = Instant::now();
    let mut scanner = Scanner::new(binary_data);
    scanner.run_full_scan(config.verbose);

    if !config.quiet && config.output_format != OutputFormat::Json {
        println!("Duration: {}ms\n", start.elapsed().as_millis());
    }

    let mut generator = ReportGenerator::new(scanner);
    generator.set_show_offsets(config.show_offsets);
    println!("{}", generator.generate(config.output_format));

    let exit_code = match generator.get_risk_score() {
        s if s >= 80 => 4,
        s if s >= 60 => 3,
        s if s >= 40 => 2,
        s if s > 0 => 1,
        _ => 0,
    };

    process::exit(exit_code);
}
