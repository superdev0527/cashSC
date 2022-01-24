use crate::unsigned_tx::{Output, PreImage, PreImageWriteFlags};
use crate::outputs::{SLPSend, P2PKHOutput};
use crate::script::{Script, Op};
use crate::address::{Address};
use crate::tx::TxOutput;
use crate::serialize::{write_var_int, var_int_to_vec, encode_int};

use byteorder::{LittleEndian, BigEndian, WriteBytesExt};
use std::iter::repeat;


#[derive(Clone, Debug)]
pub struct AdvancedTradeOffer {
    pub value: u64,
    pub lokad_id: Vec<u8>,
    pub version: u8,
    pub power: u8,
    pub is_inverted: bool,
    pub token_id: [u8; 32],
    pub token_type: u8,
    pub sell_amount_token: u64,
    pub price: u32,
    pub dust_amount: u64,
    pub address: Address,
    pub fee_address: Option<Address>,
    pub fee_divisor: Option<u64>,
    pub spend_params: Option<AdvancedTradeOfferSpendParams>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdvancedTradeOfferSpendParams {
    AcceptPartially {
        buy_amount: u64,
    },
    AcceptFully,
    Cancel,
}

impl AdvancedTradeOffer {
    fn _make_power_vec(&self) -> Vec<u8> {
        let mut vec = vec![self.power];
        if self.is_inverted {
            vec.push(1)
        }
        vec
    }

    fn _ops(&self) -> Vec<Op> {
        use crate::script::OpCodeType::*;
        let serialize = vec![
            Op::Push(vec![0x04]),
            Op::Code(OpNum2Bin),

            Op::Push(vec![1]),
            Op::Code(OpSplit),
            Op::Push(vec![1]),
            Op::Code(OpSplit),
            Op::Push(vec![1]),
            Op::Code(OpSplit),

            Op::Code(OpSwap),
            Op::Code(OpCat),
            Op::Code(OpSwap),
            Op::Code(OpCat),
            Op::Code(OpSwap),
            Op::Code(OpCat),
        ];
        let mut ops = vec![
            Op::Push({
                let mut sell_amount_serialized = Vec::new();
                sell_amount_serialized.write_u32::<LittleEndian>(self.sell_amount_token as u32).unwrap();
                sell_amount_serialized
            }),
            Op::Code(OpCodeSeparator),
            Op::Push(self.address.bytes().to_vec()),
            Op::Code(OpRot),
            Op::Code(OpIf),
            Op::Code(OpToAltStack),
            Op::Code(OpBin2Num),
        ];
        ops.append(&mut if !self.is_inverted {
            vec![
                Op::Code(OpOver),
                Op::Code(OpDup),
                Op::Push(encode_int(0)),
                Op::Code(OpGreaterThan),
                Op::Code(OpVerify),
                Op::Push(encode_int(self.price as i32)),
                Op::Code(OpDiv),
                Op::Code(OpTuck),
                Op::Code(Op2Dup),
                Op::Code(OpGreaterThanOrEqual),
                Op::Code(OpVerify),
            ]
        } else {
            vec![
                Op::Code(Op2Dup),
                Op::Code(OpLessThanOrEqual),
                Op::Code(OpVerify),
                Op::Code(OpOver),
                Op::Code(OpDup),
                Op::Push(encode_int(0)),
                Op::Code(OpGreaterThan),
                Op::Code(OpVerify),
                Op::Code(OpTuck),
            ]
        });
        ops.append(&mut vec![
            Op::Code(OpSub),
            Op::Code(OpTuck),
            Op::Code(OpDup),
            Op::Code(Op0NotEqual),
            Op::Code(OpIf),
        ]);
        ops.extend(serialize.iter().cloned());
        ops.append(&mut vec![
            Op::Push(vec![0x08]),
            Op::Push(vec![0x09]),
            Op::Code(OpNum2Bin),
            Op::Code(OpCat),
            Op::Code(OpElse),

            Op::Push(vec![0x04]),
            Op::Code(OpNum2Bin),

            Op::Code(OpEndIf),
            //Op::Push(b"\x08\0\0\0\0\0\0\0\0".to_vec()),
            //Op::Push(b"\x08\0\0\0\0".to_vec()),
            Op::Push(vec![0x08]),
            Op::Push(vec![0x05]),
            Op::Code(OpNum2Bin),
            Op::Code(OpCat),
            Op::Push(vec![0x02]),
            Op::Code(OpPick),
            Op::Code(Op0NotEqual),

            Op::Push(vec![]),
            Op::Push(vec![0x08]),
            Op::Code(OpNum2Bin),
            Op::Code(OpSwap),

            Op::Code(OpIf),
            Op::Push(var_int_to_vec(
                SLPSend {
                    token_id: self.token_id,
                    token_type: self.token_type,
                    output_quantities: vec![0, 0, 0],
                }.into_output().script().to_vec().len() as u64
            )),
            Op::Code(OpElse),
            Op::Push(var_int_to_vec(
                SLPSend {
                    token_id: self.token_id,
                    token_type: self.token_type,
                    output_quantities: vec![0, 0],
                }.into_output().script().to_vec().len() as u64
            )),
            Op::Code(OpEndIf),
            Op::Code(OpCat),

            Op::Push({
                let slp_output = SLPSend {
                    token_id: self.token_id,
                    token_type: self.token_type,
                    output_quantities: vec![],
                }.into_output();
                let mut output_pre1 = Vec::new();
                output_pre1.append(&mut slp_output.script().to_vec());
                output_pre1.append(&mut b"\x08\0\0\0\0".to_vec());
                output_pre1
            }),
            Op::Code(OpCat),
            Op::Code(OpSwap),
            Op::Code(OpCat),
            Op::Code(OpSwap),
        ]);
        ops.extend(serialize.iter().cloned());
        ops.append(&mut vec![
            Op::Code(OpCat),
            Op::Code(OpOver),
            Op::Code(Op0NotEqual),
            Op::Code(OpIf),

            Op::Push(encode_int(self.dust_amount as i32)),
            Op::Push(vec![0x08]),
            Op::Code(OpNum2Bin),  // push dust 8 bytes little endian

            Op::Push({
                let mut dust_amount_serialized = Vec::new();
                dust_amount_serialized.write_u8(23).unwrap();  // 23 = len P2SH
                dust_amount_serialized.write_u8(OpHash160 as u8).unwrap();
                dust_amount_serialized.write_u8(20).unwrap();  // 20 = len address
                dust_amount_serialized
            }),
            Op::Code(OpCat),
            Op::Code(OpCat),
            Op::Code(OpSwap),
            Op::Push(vec![0x04]),
            Op::Code(OpNum2Bin),
            Op::Push(vec![0x04]),
            Op::Code(OpSwap),
            Op::Code(OpCat),
            Op::Push(vec![OpCodeSeparator as u8]),
            Op::Code(OpCat),
            Op::Push(vec![0x06]),
            Op::Code(OpPick),
            Op::Code(OpCat),
            Op::Code(OpHash160),
            Op::Push(vec![OpEqual as u8]),
            Op::Code(OpCat),
            Op::Code(OpCat),
            Op::Code(OpElse),
            Op::Code(OpNip),
            Op::Code(OpEndIf),
            Op::Code(OpSwap),
        ]);
        if self.is_inverted {
            ops.append(&mut vec![
                Op::Push(encode_int(self.price as i32)),
                Op::Code(Op2Dup),
                Op::Code(OpMod),
                Op::Push(encode_int(0)),
                Op::Code(OpNumEqualVerify),
                Op::Code(OpDiv),
            ]);
        }
        let mut push_fee_ops = match (&self.fee_address, self.fee_divisor) {
            (Some(fee_address), Some(fee_divisor)) => {
                ops.push(Op::Code(OpTuck));
                let mut send_fee_script = Vec::new();
                let mut send_fee_output = P2PKHOutput {
                    value: 0,
                    address: fee_address.clone(),
                }.script().to_vec();
                write_var_int(&mut send_fee_script, send_fee_output.len() as u64).unwrap();
                send_fee_script.append(&mut send_fee_output);
                vec![
                    Op::Code(OpRot),
                    Op::Code(OpCat),
                    Op::Code(OpSwap),
                    Op::Push(encode_int(fee_divisor as i32)),
                    Op::Code(OpDiv),
                    Op::Push(encode_int(self.dust_amount as i32)),
                    Op::Code(OpMax),
                    Op::Push(vec![0x08]),
                    Op::Code(OpNum2Bin),
                    Op::Push(send_fee_script),
                    Op::Code(OpCat),
                    Op::Code(OpCat),
                ]
            },
            (None, None) => vec![
                Op::Code(OpSwap),
                Op::Code(OpCat),
            ],
            _ => panic!("Set fee_address and fee_divisor either both Some or None"),
        };
        ops.append(&mut vec![
            Op::Push(vec![0x08]),
            Op::Code(OpNum2Bin),
            Op::Code(OpCat),
            Op::Push({
                let p2pkh_serialized = P2PKHOutput {
                    value: 0,
                    address: self.address.clone(),
                }.script().to_vec();
                let mut vec = Vec::new();
                write_var_int(&mut vec, p2pkh_serialized.len() as u64).unwrap();
                vec.append(&mut vec![OpDup as u8, OpHash160 as u8, 20]);
                vec
            }),
            Op::Code(OpFromAltStack),
            Op::Code(OpDup),
            Op::Code(OpToAltStack),
            Op::Code(OpCat),
            Op::Push(vec![OpEqualVerify as u8, OpCheckSig as u8]),
            Op::Code(OpCat),
            Op::Code(OpCat),
        ]);
        ops.append(&mut push_fee_ops);
        ops.append(&mut vec![
            Op::Code(OpHash256),
            Op::Code(OpSwap),
            Op::Code(OpCat),
            Op::Code(OpCat),
            Op::Code(OpCat),
            Op::Code(OpCat),
            Op::Code(OpSha256),
            Op::Code(OpOver),
            Op::Push(vec![0x41]),
            Op::Code(OpCat),
            Op::Push(vec![0x03]),
            Op::Code(OpPick),
            Op::Code(OpCheckSigVerify),
            Op::Code(OpRot),
            Op::Code(OpCheckDataSigVerify),

            Op::Code(OpFromAltStack),
            Op::Code(OpEqualVerify), // address

            Op::Push({
                let mut vec = Vec::new();
                vec.write_u32::<BigEndian>(self.price).unwrap();
                vec
            }),
            Op::Code(OpEqualVerify), // price

            Op::Push(self._make_power_vec()),
            Op::Code(OpEqualVerify), // power (amount*256^power)

            Op::Push(vec![self.version]),
            Op::Code(OpEqualVerify), // version

            Op::Push(self.lokad_id.clone()),  // lokad id
            Op::Code(OpEqual),

            Op::Code(OpElse),

            Op::Code(OpNip),
            Op::Code(OpOver),
            Op::Code(OpHash160),
            Op::Code(OpEqualVerify),
            Op::Code(OpCheckSig),

            Op::Code(OpEndIf),
        ]);
        ops
    }
}

impl Output for AdvancedTradeOffer {
    fn value(&self) -> u64 {
        self.value
    }

    fn script(&self) -> Script {
        Script::new(self._ops())
    }

    fn script_code(&self) -> Script {
        Script::new(self._ops())
    }

    fn sig_script(&self,
                  mut serialized_sig: Vec<u8>,
                  serialized_pub_key: Vec<u8>,
                  pre_image: &PreImage,
                  outputs: &[TxOutput]) -> Script {
        use crate::advanced_trade_offer::AdvancedTradeOfferSpendParams::*;
        let accept_fully_amount = if self.is_inverted {
            self.sell_amount_token
        } else {
            self.sell_amount_token * (self.price as u64)
        };
        let (buy_amount, is_accept_fully) = match self.spend_params {
            Some(Cancel) => {
                return Script::new(vec![
                    Op::Push(serialized_sig),
                    Op::Push(serialized_pub_key),
                    Op::Push(vec![]),
                ])
            },
            Some(AcceptFully) => {(accept_fully_amount, true)},
            Some(AcceptPartially {buy_amount}) => (buy_amount, buy_amount == accept_fully_amount),
            None => panic!("Spend params not set"),
        };
        serialized_sig.remove(serialized_sig.len() - 1);
        let script_code = self.script_code().to_vec_sig();
        Script::new(vec![
            Op::Push(self.lokad_id.clone()),
            Op::Push(vec![self.version]),
            Op::Push(self._make_power_vec()),
            Op::Push({
                let mut vec = Vec::new();
                vec.write_u32::<BigEndian>(self.price).unwrap();
                vec
            }),
            Op::Push(self.address.bytes().to_vec()),
            Op::Push(serialized_pub_key),
            Op::Push(serialized_sig),
            Op::Push({
                let mut pre_image_part = Vec::new();
                pre_image.write_to_stream_flags(&mut pre_image_part, PreImageWriteFlags {
                    version: true,       // /-
                    hash_prevouts: true, // |
                    hash_sequence: true, // |
                    outpoint: true,      // \-
                    script_code: false,  // + len(script_code)
                    value: false,
                    sequence: false,
                    hash_outputs: false,
                    lock_time: false,
                    sighash_type: false,
                }).unwrap();
                write_var_int(&mut pre_image_part, script_code.len() as u64).unwrap();
                pre_image_part
            }),
            Op::Push(script_code),
            Op::Push({
                let mut pre_image_part = Vec::new();
                pre_image.write_to_stream_flags(&mut pre_image_part, PreImageWriteFlags {
                    version: false,
                    hash_prevouts: false,
                    hash_sequence: false,
                    outpoint: false,
                    script_code: false,
                    value: true,    // /-
                    sequence: true, // \-
                    hash_outputs: false,
                    lock_time: false,
                    sighash_type: false,
                }).unwrap();
                pre_image_part
            }),
            Op::Push({
                let mut pre_image_part = Vec::new();
                pre_image.write_to_stream_flags(&mut pre_image_part, PreImageWriteFlags {
                    version: false,
                    hash_prevouts: false,
                    hash_sequence: false,
                    outpoint: false,
                    script_code: false,
                    value: false,
                    sequence: false,
                    hash_outputs: false,
                    lock_time: true,    // /-
                    sighash_type: true, // \-
                }).unwrap();
                pre_image_part
            }),
            Op::Push({
                let mut outputs_end = Vec::new();
                outputs[
                    if is_accept_fully {2} else {3} ..
                        outputs.len() - if self.fee_address.is_some() {1} else {0}
                ].iter()
                    .for_each(|tx_output| {
                        tx_output.write_to_stream(&mut outputs_end).unwrap()
                    });
                outputs_end
            }),
            Op::Push(encode_int(buy_amount as i32)),
            Op::Push(encode_int(1)),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct P2PKHDropNOutput {
    pub value: u64,
    pub address: Address,
    pub drop_number: usize,
    pub push_data: Option<Vec<Vec<u8>>>
}


impl Output for P2PKHDropNOutput {
    fn value(&self) -> u64 {
        self.value
    }

    fn script(&self) -> Script {
        use crate::script::OpCodeType::*;
        let mut ops = vec![
            Op::Code(OpDup),
            Op::Code(OpHash160),
            Op::Push(self.address.bytes().to_vec()),
            Op::Code(OpEqualVerify),
            Op::Code(OpCheckSig),
        ];
        ops.extend(repeat(Op::Code(OpNip)).take(self.drop_number));
        Script::new(ops)
    }

    fn script_code(&self) -> Script {
        self.script()
    }

    fn sig_script(&self,
                  serialized_sig: Vec<u8>,
                  serialized_pub_key: Vec<u8>,
                  _pre_image: &PreImage,
                  _outputs: &[TxOutput]) -> Script {
        let pushes = self.push_data.as_ref().expect("Spend data not set").clone();
        if pushes.len() != self.drop_number {
            panic!(format!("push_data should be {} items but is {}",
                           self.drop_number,
                           pushes.len()))
        }
        let mut ops: Vec<Op> = pushes.into_iter().map(|push| Op::Push(push)).collect();
        ops.append(&mut vec![
            Op::Push(serialized_sig),
            Op::Push(serialized_pub_key),
        ]);
        Script::new(ops)
    }
}
