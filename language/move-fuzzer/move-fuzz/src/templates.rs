macro_rules! cargo_toml_template {
    ($name:expr, $edition:expr, $fuzzing_workspace:expr) => {
        format_args!(
            r##"[package]
name = "{name}-fuzz"
version = "0.0.0"
publish = false
{edition}
[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer = {{ path = "../../libfuzzer" }}

[dependencies.{name}]
path = ".."
{workspace}"##,
            name = $name,
            edition = if let Some(edition) = &$edition {
                format!("edition = \"{}\"\n", edition)
            } else {
                String::new()
            },
            workspace = if let Some(true) = $fuzzing_workspace {
                r##"
# Use independent workspace for fuzzers
[workspace]
members = ["."]
"##
            } else {
                "[workspace]" // todo: capire come rimettere stringa vuota senza rompere tutto
            }
        )
    };
}

macro_rules! move_toml_template {
    ($name:expr, $edition:expr) => {
        format_args!(
            r##"[package]
name = "{name}_target"
version = "0.0.0"
{edition}

[dependencies]
MoveStdlib = {{ git = "https://github.com/move-language/move.git", subdir = "language/move-stdlib", rev = "main" }}
MoveNursery = {{ git = "https://github.com/move-language/move.git", subdir = "language/move-stdlib/nursery", rev = "main" }}

[addresses]
std =  "0x1""##,
            name = $name,
            edition = if let Some(edition) = &$edition {
                format!("edition = \"{}\"\n", edition)
            } else {
                String::new()
            }
        )
    };
}

macro_rules! toml_bin_template {
    ($name: expr) => {
        format_args!(
            r#"
[[bin]]
name = "{0}"
path = "fuzz_targets/{0}.rs"
test = false
doc = false
bench = false
"#,
            $name
        )
    };
}

macro_rules! gitignore_template {
    () => {
        format_args!(
            r##"target
corpus
artifacts
coverage
"##
        )
    };
}

macro_rules! rust_target_template {
    ($edition:expr) => {
        format_args!(
            r##"#![no_main]
{extern_crate}
use libfuzzer::fuzz_target;
use libfuzzer::run_move::move_args::MoveArg;

fuzz_target!(|data: Vec<u8>| {{
    // data generation logic goes here
    vec![Box::new(data)]
}});
"##,
            extern_crate = match $edition.as_deref() {
                None | Some("2015") => "\nextern crate libfuzzer;\n",
                Some(_) => "",
            },
        )
    };
}

macro_rules! move_target_template {
    ($edition:expr) => {
        format_args!(
            r##"script {{
    fun main(data: vector<u8>) {{
        // fuzzing code goes here
    }}
}}
"##
        )
    };
}
