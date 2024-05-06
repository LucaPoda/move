use std::fmt::Debug;
use move_core_types::transaction_argument::TransactionArgument;
use move_core_types::u256::U256;

///
/// Trait to map which rust type can be an input for a move script
///
pub trait ToTransactionArgument: Debug {
    ///
    /// Method to convert a type into a transaction argument
    ///
    fn to_transaction_argument(&self) -> Vec<TransactionArgument>;
}

///
/// docs
///
pub type MoveArg = Vec<Box<dyn ToTransactionArgument>>;

impl ToTransactionArgument for u8 {
    fn to_transaction_argument(&self) -> Vec<TransactionArgument> {
        return vec![TransactionArgument::U8(*self)]
    }
}

impl ToTransactionArgument for u16 {
    fn to_transaction_argument(&self) -> Vec<TransactionArgument> {
        return vec![TransactionArgument::U16(*self)]
    }
}

impl ToTransactionArgument for u32 {
    fn to_transaction_argument(&self) -> Vec<TransactionArgument> {
        return vec![TransactionArgument::U32(*self)]
    }
}

impl ToTransactionArgument for u64 {
    fn to_transaction_argument(&self) -> Vec<TransactionArgument> {
        return vec![TransactionArgument::U64(*self)]
    }
}

impl ToTransactionArgument for u128 {
    fn to_transaction_argument(&self) -> Vec<TransactionArgument> {
        return vec![TransactionArgument::U128(*self)]
    }
}

impl ToTransactionArgument for U256 {
    fn to_transaction_argument(&self) -> Vec<TransactionArgument> {
        return vec![TransactionArgument::U256(*self)]
    }
}

impl ToTransactionArgument for bool {
    fn to_transaction_argument(&self) -> Vec<TransactionArgument> {
        return vec![TransactionArgument:: Bool(*self)]
    }
}

impl ToTransactionArgument for Vec<u8> {
    fn to_transaction_argument(&self) -> Vec<TransactionArgument> {
        return vec![TransactionArgument::U8Vector(self.to_vec())]
    }
}

impl ToTransactionArgument for Vec<Box<dyn ToTransactionArgument>> {
    fn to_transaction_argument(&self) -> Vec<TransactionArgument> {
        let mut res = Vec::new();
        for arg in self {
            for sub_arg in arg.to_transaction_argument() {
                res.push(sub_arg);
            }
        }
        res
    }
}