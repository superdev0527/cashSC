use crate::address::{Address, AddressError};
use crate::unsigned_tx::{UnsignedTx, UnsignedInput, Output};
use crate::tx::{TxOutpoint, tx_hex_to_hash};
use crate::outputs::P2PKHOutput;


pub struct Wallet {
    address: Address,
    fee_per_kb: u64,
}

pub struct UtxoEntry {
    pub tx_id_hex: String,
    pub vout: u32,
    pub amount: u64,
}

pub const DUST_AMOUNT: u64 = 546;

impl Wallet {
    pub fn from_cash_addr(cash_addr: String) -> Result<Self, AddressError> {
        let addr = Address::from_cash_addr(cash_addr)?;
        Ok(Wallet {
            address: addr,
            fee_per_kb: 1000,
        })
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn init_tx(&self, utxos: &[UtxoEntry]) -> UnsignedTx {
        let mut tx_build = UnsignedTx::new_simple();
        for utxo in utxos {
            tx_build.add_input(UnsignedInput {
                output: Box::new(P2PKHOutput {
                    address: self.address.clone(),
                    value: utxo.amount,
                }),
                outpoint: TxOutpoint {
                    tx_hash: tx_hex_to_hash(&utxo.tx_id_hex).unwrap(),
                    vout: utxo.vout,
                },
                sequence: 0xffff_ffff,
            });
        }
        tx_build
    }

    pub fn send_to_address(&self, address: Address, amount: u64, utxos: &[UtxoEntry])
            -> Result<UnsignedTx, u64> {
        let mut tx_build = self.init_tx(utxos);
        tx_build.add_output(P2PKHOutput {
            address,
            value: amount,
        }.to_output());
        tx_build.add_leftover_output(self.address.clone(), self.fee_per_kb, self.dust_amount())?;
        Ok(tx_build)
    }

    pub fn dust_amount(&self) -> u64 {
        DUST_AMOUNT
    }
}
