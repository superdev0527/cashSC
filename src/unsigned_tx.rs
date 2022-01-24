use crate::tx::{TxInput, TxOutput, TxOutpoint, Tx};
use crate::outputs::P2PKHOutput;
use crate::script::*;
use crate::hash::{double_sha256};
use crate::serialize::write_var_int;
use crate::address::Address;

use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};

const MAX_SIGNATURE_SIZE: usize = 73;  // explained https://bitcoin.stackexchange.com/a/77192
const PUBKEY_SIZE: usize = 33;

pub trait Output {
    fn value(&self) -> u64;
    fn script(&self) -> Script;
    fn script_code(&self) -> Script;
    fn sig_script(&self,
                  serialized_sig: Vec<u8>,
                  serialized_pub_key: Vec<u8>,
                  pre_image: &PreImage,
                  outputs: &[TxOutput]) -> Script;
    fn to_output(&self) -> TxOutput {
        TxOutput {
            value: self.value(),
            script: self.script(),
        }
    }
}


pub struct UnsignedInput {
    pub outpoint: TxOutpoint,
    pub output: Box<dyn Output>,
    pub sequence: u32,
}

#[derive(Clone, Debug)]
pub struct PreImage {
    pub version: i32,
    pub hash_prevouts: [u8; 32],
    pub hash_sequence: [u8; 32],
    pub outpoint: TxOutpoint,
    pub script_code: Script,
    pub value: u64,
    pub sequence: u32,
    pub hash_outputs: [u8; 32],
    pub lock_time: u32,
    pub sighash_type: u32,
}

pub struct UnsignedTx {
    version: i32,
    inputs: Vec<UnsignedInput>,
    outputs: Vec<TxOutput>,
    lock_time: u32,
}

impl UnsignedTx {
    pub fn new_simple() -> Self {
        UnsignedTx {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        }
    }

    pub fn new_locktime(lock_time: u32) -> Self {
        UnsignedTx {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time,
        }
    }

    pub fn add_input(&mut self, input: UnsignedInput) -> usize {
        self.inputs.push(input);
        self.inputs.len() - 1
    }

    pub fn replace_input(&mut self, idx: usize, input: UnsignedInput) {
        self.inputs[idx] = input;
    }

    pub fn add_output(&mut self, output: TxOutput) -> usize {
        self.outputs.push(output);
        self.outputs.len() - 1
    }

    pub fn insert_output(&mut self, idx: usize, output: TxOutput) {
        self.outputs.insert(idx, output);
    }

    pub fn replace_output(&mut self, idx: usize, output: TxOutput) {
        self.outputs[idx] = output;
    }

    pub fn remove_output(&mut self, idx: usize) {
        self.outputs.remove(idx);
    }

    pub fn pre_images(&self, sighash_type: u32) -> Vec<PreImage> {
        let mut hash_prevouts = [0u8; 32];
        let mut hash_sequence = [0u8; 32];
        let mut hash_outputs = [0u8; 32];
        {
            let mut outpoints_serialized = Vec::new();
            for input in self.inputs.iter() {
                outpoints_serialized.write_all(&input.outpoint.tx_hash).unwrap();
                outpoints_serialized.write_u32::<LittleEndian>(input.outpoint.vout).unwrap();
            }
            hash_prevouts.copy_from_slice(&double_sha256(&outpoints_serialized));
        }
        {
            let mut sequence_serialized = Vec::new();
            for input in self.inputs.iter() {
                sequence_serialized.write_u32::<LittleEndian>(input.sequence).unwrap();
            }
            hash_sequence.copy_from_slice(&double_sha256(&sequence_serialized));
        }
        {
            let mut outputs_serialized = Vec::new();
            for output in self.outputs.iter() {
                println!("tx_output: {} {}", output.value, output.script);
                output.write_to_stream(&mut outputs_serialized).unwrap();
            }
            println!("outputs_serialized: {}", hex::encode(&outputs_serialized));
            hash_outputs.copy_from_slice(&double_sha256(&outputs_serialized));
        }
        let mut pre_images = Vec::new();
        for input in self.inputs.iter() {
            pre_images.push(PreImage {
                version: self.version,
                hash_prevouts,
                hash_sequence,
                outpoint: input.outpoint.clone(),
                script_code: input.output.script_code(),
                value: input.output.value(),
                sequence: input.sequence,
                hash_outputs,
                lock_time: self.lock_time,
                sighash_type,
            });
        }
        pre_images
    }

    pub fn estimate_size(&self) -> usize {
        let mut tx_inputs = Vec::with_capacity(self.inputs.len());
        for input in self.inputs.iter() {
            let sig_ser = vec![0; MAX_SIGNATURE_SIZE];
            let pub_key_ser = vec![0; PUBKEY_SIZE];
            let pre_image = PreImage::empty(input.output.script_code());
            let script = input.output.sig_script(sig_ser, pub_key_ser, &pre_image,
                                                 &self.outputs);
            tx_inputs.push(TxInput::new(input.outpoint.clone(), script, input.sequence));
        }
        let mut vec = Vec::new();
        Tx::new(self.version, tx_inputs, self.outputs.clone(), self.lock_time)
            .write_to_stream(&mut vec).unwrap();
        vec.len() + 2
    }

    pub fn insert_leftover_output(&mut self,
                                  leftover_idx: usize,
                                  leftover_addr: Address,
                                  fee_per_kb: u64,
                                  dust_limit: u64) -> Result<Option<usize>, u64> {
        let total_output_amount = self.outputs.iter()
            .map(|output| output.value)
            .sum::<u64>();
        let mut leftover = P2PKHOutput {
            value: 0xffffffff_ffffffff,  // definitely invalid
            address: leftover_addr,
        };
        let tx_size_without = self.estimate_size();
        self.insert_output(
            leftover_idx,
            TxOutput {
                value: leftover.value(),
                script: leftover.script(),
            },
        );
        let tx_size = self.estimate_size();
        let fee = tx_size as u64 * fee_per_kb / 1000;
        let fee_without = tx_size_without as u64 * fee_per_kb / 1000;
        let total_input_amount = self.inputs.iter()
            .map(|input| input.output.value())
            .sum::<u64>();
        let total_spent = total_output_amount + fee;
        let total_spent_without = total_output_amount + fee_without;
        if total_spent_without > total_input_amount {
            self.outputs.remove(leftover_idx);
            return Err(total_spent - total_input_amount);
        } else if total_input_amount - total_spent_without < dust_limit {
            self.outputs.remove(leftover_idx);
            return Ok(None);
        }
        leftover.value = total_input_amount - total_spent;
        self.replace_output(leftover_idx, TxOutput {
            value: leftover.value(),
            script: leftover.script(),
        });
        Ok(Some(leftover_idx))
    }

    pub fn add_leftover_output(&mut self, leftover_addr: Address, fee_per_kb: u64, dust_limit: u64)
            -> Result<Option<usize>, u64>{
        self.insert_leftover_output(
            self.outputs.len(),
            leftover_addr,
            fee_per_kb,
            dust_limit,
        )
    }

    pub fn sign(&self,
                serialized_signatures: Vec<Vec<u8>>,
                serialized_pub_keys: Vec<Vec<u8>>) -> Tx {
        let sighash_type: u32 = 0x41;
        let mut tx_inputs = Vec::with_capacity(self.inputs.len());
        for (((input, mut serialized_signature), serialized_pub_key), pre_image) in
                self.inputs.iter()
                    .zip(serialized_signatures)
                    .zip(serialized_pub_keys)
                    .zip(self.pre_images(sighash_type)) {
            serialized_signature.write_u8(sighash_type as u8).unwrap();
            let script = input.output.sig_script(
                serialized_signature,
                serialized_pub_key,
                &pre_image,
                &self.outputs);
            tx_inputs.push(TxInput::new(input.outpoint.clone(), script, input.sequence));
        }
        Tx::new(self.version, tx_inputs, self.outputs.clone(), self.lock_time)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct PreImageWriteFlags {
    pub version: bool,
    pub hash_prevouts: bool,
    pub hash_sequence: bool,
    pub outpoint: bool,
    pub script_code: bool,
    pub value: bool,
    pub sequence: bool,
    pub hash_outputs: bool,
    pub lock_time: bool,
    pub sighash_type: bool,
}

impl PreImage {
    pub fn empty(script_code: Script) -> Self {
        PreImage {
            version: 0,
            hash_prevouts: [0; 32],
            hash_sequence: [0; 32],
            outpoint: TxOutpoint {
                vout: 0,
                tx_hash: [0; 32],
            },
            script_code,
            value: 0,
            sequence: 0,
            hash_outputs: [0; 32],
            lock_time: 0,
            sighash_type: 0,
        }
    }

    pub fn write_to_stream_flags<W: Write>(&self,
                                           write: &mut W,
                                           flags: PreImageWriteFlags) -> std::io::Result<()> {
        if flags.version       { write.write_i32::<LittleEndian>(self.version)?; }
        if flags.hash_prevouts { write.write_all(&self.hash_prevouts)?; }
        if flags.hash_sequence { write.write_all(&self.hash_sequence)?; }
        if flags.outpoint {
            write.write_all(&self.outpoint.tx_hash)?;
            write.write_u32::<LittleEndian>(self.outpoint.vout)?;
        }
        if flags.script_code {
            let script = self.script_code.to_vec_sig();
            write_var_int(write, script.len() as u64)?;
            write.write_all(&script)?;
        }
        if flags.value        { write.write_u64::<LittleEndian>(self.value)?; }
        if flags.sequence     { write.write_u32::<LittleEndian>(self.sequence)?; }
        if flags.hash_outputs { write.write_all(&self.hash_outputs)?; }
        if flags.lock_time    { write.write_u32::<LittleEndian>(self.lock_time)?; }
        if flags.sighash_type { write.write_u32::<LittleEndian>(self.sighash_type)?; }
        Ok(())
    }

    pub fn write_to_stream<W: Write>(&self, write: &mut W) -> std::io::Result<()> {
        self.write_to_stream_flags(write, PreImageWriteFlags {
            version: true,
            hash_prevouts: true,
            hash_sequence: true,
            outpoint: true,
            script_code: true,
            value: true,
            sequence: true,
            hash_outputs: true,
            lock_time: true,
            sighash_type: true,
        })
    }
}

impl std::fmt::Display for PreImage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "version: {}", self.version)?;
        writeln!(f, "hash_prevouts: {}", hex::encode(self.hash_prevouts))?;
        writeln!(f, "hash_sequence: {}", hex::encode(self.hash_sequence))?;
        writeln!(f, "outpoint.tx_hash: {}", hex::encode(self.outpoint.tx_hash))?;
        writeln!(f, "outpoint.output_idx: {}", self.outpoint.vout)?;
        writeln!(f, "script_code: {}", hex::encode(self.script_code.to_vec()))?;
        writeln!(f, "value: {}", self.value)?;
        writeln!(f, "sequence: {}", self.sequence)?;
        writeln!(f, "hash_outputs: {}", hex::encode(self.hash_outputs))?;
        writeln!(f, "lock_time: {}", self.lock_time)?;
        writeln!(f, "sighash_type: {:x}", self.sighash_type)?;
        Ok(())
    }
}
