use crate::serialize::{write_var_int, read_var_int};
use crate::script::Script;
use crate::hash::double_sha256;

use std::io;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};


#[derive(Clone, Debug)]
pub struct TxOutpoint {
    pub tx_hash: [u8; 32],
    pub vout: u32,
}

#[derive(Clone, Debug)]
pub struct TxInput {
    pub outpoint: TxOutpoint,
    pub script: Script,
    pub sequence: u32,
}

#[derive(Clone, Debug)]
pub struct TxOutput {
    pub value: u64,
    pub script: Script,
}

#[derive(Clone, Debug)]
pub struct Tx {
    version: i32,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    lock_time: u32,
}

pub fn tx_hex_to_hash(s: &str) -> Option<[u8; 32]> {
    let mut tx_hash = [0; 32];
    let tx_hash_slice = hex::decode(s).ok()?;
    if tx_hash_slice.len() != 32 { return None; }
    tx_hash.copy_from_slice(&tx_hash_slice.iter().rev().cloned().collect::<Vec<_>>());
    Some(tx_hash)
}

pub fn tx_hash_to_hex(tx_hash: &[u8; 32]) -> String {
    hex::encode(&tx_hash.iter().rev().cloned().collect::<Vec<_>>())
}

impl TxOutpoint {
    pub fn bytes(&self) -> [u8; 36] {
        let mut key = [0u8; 32 + 4];
        key[..32].copy_from_slice(&self.tx_hash);
        key[32..].copy_from_slice(&self.vout.to_le_bytes());
        key
    }
}

impl TxInput {
    pub fn new(outpoint: TxOutpoint,
               script: Script,
               sequence: u32) -> Self {
        TxInput { outpoint, script, sequence }
    }

    pub fn script(&self) -> &Script {
        &self.script
    }

    pub fn read_from_stream<R: io::Read>(read: &mut R) -> io::Result<Self> {
        let mut tx_hash = [0; 32];
        read.read_exact(&mut tx_hash)?;
        let vout = read.read_u32::<LittleEndian>()?;
        let script_len = read_var_int(read)?;
        let mut script = vec![0; script_len as usize];
        read.read_exact(&mut script[..])?;
        let sequence = read.read_u32::<LittleEndian>()?;
        Ok(TxInput {
            outpoint: TxOutpoint {tx_hash, vout},
            script: Script::from_serialized(&script)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid script"))?,
            sequence,
        })
    }

    pub fn write_to_stream<W: io::Write>(&self, write: &mut W) -> io::Result<()> {
        write.write_all(&self.outpoint.tx_hash)?;
        write.write_u32::<LittleEndian>(self.outpoint.vout)?;
        let script = self.script.to_vec();
        write_var_int(write, script.len() as u64)?;
        write.write_all(&script)?;
        write.write_u32::<LittleEndian>(self.sequence)?;
        Ok(())
    }
}

impl TxOutput {
    pub fn new(value: u64,
               script: Script) -> Self {
        TxOutput { value, script }
    }

    pub fn read_from_stream<R: io::Read>(read: &mut R) -> io::Result<Self> {
        let value = read.read_u64::<LittleEndian>()?;
        let script_len = read_var_int(read)?;
        let mut script = vec![0; script_len as usize];
        read.read_exact(&mut script[..])?;
        Ok(TxOutput {
            value,
            script: Script::from_serialized(&script)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid script"))?,
        })
    }

    pub fn write_to_stream<W: io::Write>(&self, write: &mut W) -> io::Result<()> {
        write.write_u64::<LittleEndian>(self.value)?;
        let script = self.script.to_vec();
        write_var_int(write, script.len() as u64)?;
        write.write_all(&script)?;
        Ok(())
    }

    pub fn script(&self) -> &Script {
        &self.script
    }
}

impl Tx {
    pub fn new(version: i32,
               inputs: Vec<TxInput>,
               outputs: Vec<TxOutput>,
               lock_time: u32) -> Self {
        Tx { version, inputs, outputs, lock_time }
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut vec = Vec::new();
        self.write_to_stream(&mut vec).unwrap();
        double_sha256(&vec)
    }

    pub fn read_from_stream<R: io::Read>(read: &mut R) -> io::Result<Self> {
        let version = read.read_i32::<LittleEndian>()?;
        let num_inputs = read_var_int(read)?;
        let mut inputs = Vec::new();
        for _ in 0..num_inputs {
            inputs.push(TxInput::read_from_stream(read)?);
        }
        let num_outputs = read_var_int(read)?;
        let mut outputs = Vec::new();
        for _ in 0..num_outputs {
            outputs.push(TxOutput::read_from_stream(read)?);
        }
        let lock_time = read.read_u32::<LittleEndian>()?;
        Ok(Tx { version, inputs, outputs, lock_time })
    }

    pub fn write_to_stream<W: io::Write>(&self, write: &mut W) -> io::Result<()> {
        write.write_i32::<LittleEndian>(self.version)?;
        write_var_int(write, self.inputs.len() as u64)?;
        for input in self.inputs.iter() {
            input.write_to_stream(write)?;
        }
        write_var_int(write, self.outputs.len() as u64)?;
        for output in self.outputs.iter() {
            output.write_to_stream(write)?;
        }
        write.write_u32::<LittleEndian>(self.lock_time)?;
        Ok(())
    }

    pub fn inputs(&self) -> &[TxInput] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[TxOutput] {
        &self.outputs
    }
}
