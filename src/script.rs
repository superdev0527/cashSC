use std::io;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};


#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Op {
    Push(Vec<u8>),
    Code(OpCodeType),
}

impl Op {
    pub fn code(&self) -> u8 {
        match self {
            Op::Push(vec) => {
                match vec.len() {
                    0 ..= 0x4b        => vec.len() as u8,
                    0x4c ..= 0xff     => 0x4c,
                    0x100 ..= 0xffff  => 0x4d,
                    0x10000 ..= 0xffff_ffff => 0x4e,
                    _                 => unimplemented!(),
                }
            },
            Op::Code(code) => *code as u8,
        }
    }

    pub fn write_to_stream<W: io::Write>(&self, write: &mut W, is_minimal_push: bool) -> io::Result<()> {
        if let Op::Push(vec) = self {
            if vec.is_empty() && !is_minimal_push {
                write.write_u8(0x4c)?;
                return write.write_u8(0)
            }
            if vec.len() == 1 && is_minimal_push && vec[0] > 0 && vec[0] <= 16 {
                return write.write_u8(vec[0] + 0x50)
            }
            write.write_u8(self.code())?;
            match vec.len() {
                0 ..= 0x4b => {},
                len @ (0 ..= 0xff) => { write.write_u8(len as u8)? },
                len @ (0 ..= 0xffff) => { write.write_u16::<LittleEndian>(len as u16)? },
                len @ (0 ..= 0xffff_ffff) => { write.write_u32::<LittleEndian>(len as u32)? },
                _ => {},
            };
            write.write_all(vec)?;
        } else {
            write.write_u8(self.code())?;
        }
        Ok(())
    }
}

impl std::fmt::Display for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Op::Push(vec) => write!(f, "PUSH {}", hex::encode(vec)),
            Op::Code(code) => write!(f, "{:?}", code),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Script {
    ops: Vec<Op>,
    serialized: Option<Vec<u8>>,
    is_minimal_push: bool,
    is_slp_safe: bool,
}

impl Script {
    pub fn empty() -> Self {
        Script { ops: vec![], is_minimal_push: true, is_slp_safe: true, serialized: None }
    }

    pub fn new(ops: Vec<Op>) -> Self {
        Script { ops, is_minimal_push: true, is_slp_safe: false, serialized: None }
    }

    pub fn new_non_minimal_push(ops: Vec<Op>) -> Self {
        Script {
            ops,
            is_minimal_push: false,
            is_slp_safe: false,
            serialized: None,
        }
    }

    pub fn from_serialized(data: &[u8]) -> Option<Self> {
        let mut ops = Vec::new();
        let mut idx = 0;
        let mut is_slp_safe = true;
        while idx < data.len() {
            match data[idx] {
                0 => {
                    ops.push(Op::Push(vec![]));
                    is_slp_safe = false;
                }
                n_bytes @ (1 ..= 0x4b) => {
                    let n_bytes = n_bytes as usize;
                    let offset = idx + 1;
                    if offset + n_bytes > data.len() { return None; }
                    ops.push(Op::Push(data[offset..offset + n_bytes].to_vec()));
                    idx += n_bytes;
                },
                push_length @ (0x4c..=0x4e) => {
                    let offset = idx + 1;
                    let mut cur = io::Cursor::new(&data[offset..]);
                    let n_bytes = match push_length {
                        0x4c => { idx += 1; cur.read_u8().ok()? as usize},
                        0x4d => { idx += 2; cur.read_u16::<LittleEndian>().ok()? as usize },
                        0x4e => { idx += 4; cur.read_u32::<LittleEndian>().ok()? as usize },
                        _ => unreachable!(),
                    };
                    if offset + n_bytes > data.len() { return None; }
                    ops.push(Op::Push(data[offset..offset + n_bytes].to_vec()));
                    idx += n_bytes;
                },
                code => {
                    let code = Op::Code(
                        num::FromPrimitive::from_u8(code).unwrap_or(OpCodeType::OpInvalidOpcode)
                    );
                    if idx != 0 && code != Op::Code(OpCodeType::OpReturn) {
                        is_slp_safe = false;
                    }
                    ops.push(code);
                },
            }
            idx += 1;
        }
        Some(Script {
            ops,
            is_minimal_push: true,  // TODO: may need to figure this out
            is_slp_safe,
            serialized: Some(data.to_vec())
        })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        if let Some(vec) = &self.serialized {
            return vec.clone();
        }
        let mut vec = Vec::new();
        for op in self.ops.iter() {
            op.write_to_stream(&mut vec, self.is_minimal_push).unwrap();
        }
        vec
    }

    pub fn to_vec_sig(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        let code_separator_pos = self.ops.iter().rposition(
            |op| op == &Op::Code(OpCodeType::OpCodeSeparator)
        );
        for (idx, op) in self.ops.iter().enumerate() {
            if let Some(code_sep_pos) = code_separator_pos {
                if idx <= code_sep_pos {
                    continue;
                }
            }
            op.write_to_stream(&mut vec, self.is_minimal_push).unwrap();
        }
        vec
    }

    pub fn add_op(&mut self, op: Op) -> &mut Self {
        self.ops.push(op);
        self
    }

    pub fn extend(&mut self, mut other: Script) {
        self.ops.append(&mut other.ops);
    }

    pub fn ops(&self) -> &[Op] {
        &self.ops
    }

    pub fn is_slp_safe(&self) -> bool {
        self.is_slp_safe
    }
}

impl std::fmt::Display for Script {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "Script ({} ops):", self.ops.len())?;
        for (i, op) in self.ops.iter().enumerate() {
            write!(f, "{:3}: ", i)?;
            match op {
                Op::Push(vec) => writeln!(f, "PUSH {}", hex::encode(&vec))?,
                other => writeln!(f, "{:?}", other)?,
            };
        }
        Ok(())
    }
}

use num_derive::*;

#[derive(Clone, Debug, Copy, Eq, PartialEq, Ord, PartialOrd, FromPrimitive)]
pub enum OpCodeType {
    // push value
    Op0 = 0x00,
    OpPushData1 = 0x4c,
    OpPushData2 = 0x4d,
    OpPushData4 = 0x4e,
    Op1Negate = 0x4f,
    OpReserved = 0x50,
    Op1 = 0x51,
    Op2 = 0x52,
    Op3 = 0x53,
    Op4 = 0x54,
    Op5 = 0x55,
    Op6 = 0x56,
    Op7 = 0x57,
    Op8 = 0x58,
    Op9 = 0x59,
    Op10 = 0x5a,
    Op11 = 0x5b,
    Op12 = 0x5c,
    Op13 = 0x5d,
    Op14 = 0x5e,
    Op15 = 0x5f,
    Op16 = 0x60,

    // control
    OpNop = 0x61,
    OpVer = 0x62,
    OpIf = 0x63,
    OpNotIf = 0x64,
    OpVerIf = 0x65,
    OpVerNotIf = 0x66,
    OpElse = 0x67,
    OpEndIf = 0x68,
    OpVerify = 0x69,
    OpReturn = 0x6a,

    // stack ops
    OpToAltStack = 0x6b,
    OpFromAltStack = 0x6c,
    Op2Drop = 0x6d,
    Op2Dup = 0x6e,
    Op3Dup = 0x6f,
    Op2Over = 0x70,
    Op2Rot = 0x71,
    Op2Swap = 0x72,
    OpIfDup = 0x73,
    OpDepth = 0x74,
    OpDrop = 0x75,
    OpDup = 0x76,
    OpNip = 0x77,
    OpOver = 0x78,
    OpPick = 0x79,
    OpRoll = 0x7a,
    OpRot = 0x7b,
    OpSwap = 0x7c,
    OpTuck = 0x7d,

    // splice ops
    OpCat = 0x7e,
    OpSplit = 0x7f,   // after monolith upgrade (May 2018)
    OpNum2Bin = 0x80, // after monolith upgrade (May 2018)
    OpBin2Num = 0x81, // after monolith upgrade (May 2018)
    OpSize = 0x82,

    // bit logic
    OpInvert = 0x83,
    OpAnd = 0x84,
    OpOr = 0x85,
    OpXor = 0x86,
    OpEqual = 0x87,
    OpEqualVerify = 0x88,
    OpReserved1 = 0x89,
    OpReserved2 = 0x8a,

    // numeric
    Op1Add = 0x8b,
    Op1Sub = 0x8c,
    Op2Mul = 0x8d,
    Op2Div = 0x8e,
    OpNegate = 0x8f,
    OpAbs = 0x90,
    OpNot = 0x91,
    Op0NotEqual = 0x92,

    OpAdd = 0x93,
    OpSub = 0x94,
    OpMul = 0x95,
    OpDiv = 0x96,
    OpMod = 0x97,
    OpLShift = 0x98,
    OpRShift = 0x99,

    OpBoolAnd = 0x9a,
    OpBoolOr = 0x9b,
    OpNumEqual = 0x9c,
    OpNumEqualVerify = 0x9d,
    OpNumNotEqual = 0x9e,
    OpLessThan = 0x9f,
    OpGreaterThan = 0xa0,
    OpLessThanOrEqual = 0xa1,
    OpGreaterThanOrEqual = 0xa2,
    OpMin = 0xa3,
    OpMax = 0xa4,

    OpWithin = 0xa5,

    // crypto
    OpRipemd160 = 0xa6,
    OpSha1 = 0xa7,
    OpSha256 = 0xa8,
    OpHash160 = 0xa9,
    OpHash256 = 0xaa,
    OpCodeSeparator = 0xab,
    OpCheckSig = 0xac,
    OpCheckSigVerify = 0xad,
    OpCheckMultiSig = 0xae,
    OpCheckMultiSigVerify = 0xaf,

    // expansion
    OpNop1 = 0xb0,
    OpCheckLockTimeVerify = 0xb1,
    OpCheckSequenceVerify = 0xb2,
    OpNop4 = 0xb3,
    OpNop5 = 0xb4,
    OpNop6 = 0xb5,
    OpNop7 = 0xb6,
    OpNop8 = 0xb7,
    OpNop9 = 0xb8,
    OpNop10 = 0xb9,

    // More crypto
    OpCheckDataSig = 0xba,
    OpCheckDataSigVerify = 0xbb,

    // The first op_code value after all defined opcodes
    FirstUndefinedOpCode,

    // multi-byte opcodes
    OpPrefixBegin = 0xf0,
    OpPrefixEnd = 0xf7,

    // template matching params
    OpSmallInteger = 0xfa,
    OpPubKeys = 0xfb,
    OpPubKeyHash = 0xfd,
    OpPubkey = 0xfe,

    OpInvalidOpcode = 0xff,
}
