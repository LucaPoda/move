use anyhow::{Result, Error, anyhow};
use move_cli::{Move, DEFAULT_STORAGE_DIR, sandbox};
use move_core_types::{account_address::AccountAddress, errmap::ErrorMapping, language_storage::TypeTag, transaction_argument::TransactionArgument};
use move_stdlib::natives::{all_natives, nursery_natives, GasParameters, NurseryGasParameters};
use move_package::BuildConfig;

use std::{env, fmt, path::PathBuf, process::Command};
use std::fmt::Debug;
use move_cli::sandbox::utils::PackageContext;
use move_core_types::identifier::Identifier;

use move_core_types::u256::U256;
use move_core_types::vm_status::StatusCode;
use move_core_types::vm_status::StatusCode::ABORTED;
use move_vm_runtime::native_functions::NativeFunction;
use crate::run_move::move_args::ToTransactionArgument;
use crate::run_move::move_args::MoveArg;

///
/// todo: docs
///
pub mod move_args;


///
/// todo: docs
///
pub fn run(data: MoveArg) {
    if let Err(e) = run_aux(data) {
        panic!("{}", e);
    }
}

fn run_aux(data: MoveArg) -> Result<()> {
    let script_name = None;
    let bytecode_version : Option<u32> = None;
    let storage_dir = PathBuf::from(DEFAULT_STORAGE_DIR);
    let signers : Vec<String> = Vec::new();
    let type_args = vec![];
    let gas_budget = None;
    let dry_run = false;

    let cmd_args = env::args().collect::<Vec<String>>();
    let target_path = PathBuf::from(&cmd_args[0]);

    let target_name = target_path.file_name().unwrap();

    let target_dir = PathBuf::from("./fuzz");
    let mut script_file = target_dir.clone();
    //script_file.push(format!("sources/{}.move", target_name.to_str().unwrap()));
    script_file.push(format!("build/move-fuzz_target/bytecode_scripts/main.mv"));
    let move_args = Move {
        package_path: Some(target_dir),
        verbose: false,
        build_config: BuildConfig::default(),
    };

    let args = data.to_transaction_argument();

    let error_descriptions: ErrorMapping = bcs::from_bytes(move_stdlib::error_descriptions())?;

    let cost_table = &move_vm_test_utils::gas_schedule::INITIAL_COST_SCHEDULE;
    let addr = AccountAddress::from_hex_literal("0x1").unwrap();
    let natives : Vec<(AccountAddress, Identifier, Identifier, NativeFunction)> = all_natives(addr, GasParameters::zeros())
        .into_iter()
        .chain(nursery_natives(addr, NurseryGasParameters::zeros()))
        .collect();

    let context = PackageContext::new(&move_args.package_path, &move_args.build_config)?;

    let state = context.prepare_state(bytecode_version, &storage_dir)?;


    match sandbox::commands::run_and_check (
        natives,
        cost_table,
        &error_descriptions,
        &state,
        context.package(),
        &script_file,
        &script_name,
        &signers,
        &args,
        type_args.to_vec(),
        gas_budget,
        bytecode_version,
        dry_run,
        move_args.verbose,
    ) {
        Ok(res) => {
            if ! res {
                Err(anyhow!("Terminating execution..."))
            }
            else {
                Ok(())
            }
        }
        Err(err) => {
            Err(err)
        }
    }
}