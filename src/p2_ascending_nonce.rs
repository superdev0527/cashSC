use crate::unsigned_tx::{Output, PreImage, PreImageWriteFlags};
use crate::script::{Script, Op};
use crate::tx::TxOutput;
use crate::serialize::{write_var_int, encode_int};

use std::convert::TryInto;


#[derive(Clone, Debug)]
pub struct P2AscendingNonce {
    pub lokad_id: Vec<u8>,
    pub old_value: u64,
    pub owner_pk: Vec<u8>,
    pub old_nonce: i32,
    pub dust_limit: i32,
    pub spend_params: Option<P2AscendingNonceSpendParams>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum P2AscendingNonceSpendParams {
    NonceRedeem {
        payment_amount: i32,
        new_nonce: i32,
        owner_sig: Vec<u8>,
        is_terminal: bool,
    },
    NonceRefill {
        payment_amount: i32,
    },
    P2pk,
}

impl P2AscendingNonce {
    fn _ops(&self) -> Vec<Op> {
        use crate::script::OpCodeType::*;
        use crate::script::Op::*;
        let sign_byte = if self.old_nonce < 0 { 0x80 } else { 0 };
        let mut ops = vec![
            Push([
                self.old_nonce.abs().to_le_bytes(),
                [0, 0, 0, sign_byte],
            ].concat().to_vec()),
            Push(self.owner_pk.clone()),
            Code(OpRot),
        ];
        ops.push(Code(OpIf));
        {
            // case Nonce
            ops.append(&mut vec![
                Code(OpToAltStack),
                Code(OpBin2Num),
                Code(OpOver),
                Push(encode_int(6)),  // (=paymentAmount)
                Code(OpPick),
                Push(vec![]),
                Code(OpGreaterThanOrEqual),
            ]);
            ops.push(Code(OpIf));
            {
                // case: redeem
                ops.push(Code(OpLessThan));
            }
            ops.push(Code(OpElse));
            {
                // case: refill
                ops.push(Code(OpEqual));
            }
            ops.push(Code(OpEndIf));
            ops.append(&mut vec![
                Code(OpVerify),
                Push(vec![8]),  // (=nonce size)
                Code(OpNum2Bin),
                Code(OpDup),
                Code(OpToAltStack),
                Push(vec![0x08]), // (=PUSH 8 bytes)
                Code(OpSwap),
                Code(OpCat),
                Code(OpRot),
                Code(OpRot),
                Code(OpCat),
                Code(OpTuck),
                Code(OpCat),
                Code(OpHash160),
                Code(OpSwap),
                Code(OpToAltStack),
                Code(OpToAltStack),
                Code(Op2Dup),
                Code(OpSwap),
                Code(OpSub),
                Code(OpDup),
                Push(encode_int(self.dust_limit)),
                Code(OpGreaterThanOrEqual),
            ]);
            ops.push(Code(OpIf));
            {
                // case: above dust limit
                ops.append(&mut vec![
                    Push(vec![8]),  // (=value size)
                    Code(OpNum2Bin),
                    Push(vec![23, OpHash160 as u8, 20]),  // (=p2shpre)
                    Code(OpFromAltStack),
                    Push(vec![OpEqual as u8]),
                    Code(OpCat),
                    Code(OpCat),
                    Code(OpCat),
                ]);
            }
            ops.push(Code(OpElse));
            {
                // case: below dust limit
                ops.append(&mut vec![
                    Code(OpFromAltStack),
                    Code(Op2Drop),
                    Push(vec![]),
                ]);
            }
            ops.push(Code(OpEndIf));
            ops.append(&mut vec![
                Push(encode_int(7)),  // <outputspost>
                Code(OpRoll),
                Code(OpCat),
                Code(OpHash256),
                Code(OpSwap),
                Push(vec![8]),  // (=value size)
                Code(OpNum2Bin),
                Push(encode_int(4)),  // <preimageprefix>
                Code(OpRoll),
                Code(OpSize),
                Push(encode_int(4 + 32 + 32 + (32 + 4) + 1 + 9)),  // (=preimage prefix size)
                Code(OpNumEqualVerify),
                Code(OpFromAltStack),
                Code(OpCat),
                Code(OpSwap),
                Code(OpCat),
                Push(b"\xff\xff\xff\xff".to_vec()), // (=seq no)
                Code(OpCat),
                Code(OpSwap),
                Code(OpCat),
                Code(OpRot),
                Code(OpSize),
                Push(vec![8]),  // (=preimage suffix size)
                Code(OpNumEqualVerify),
                Code(OpCat),
                Code(OpSha256),
                Code(Op2Swap),
                Code(OpOver),
                Code(OpToAltStack),
                Code(Op2Dup),
                Push(vec![0x41]),  //  (=sighash_all)
                Code(OpCat),
                Code(OpSwap),
                Code(OpCheckSigVerify),
                Code(OpRot),
                Code(OpRot),
                Code(OpCheckDataSigVerify),
                Code(OpDup),
                Push(vec![]),
                Code(OpGreaterThanOrEqual),
            ]);
            ops.push(Code(OpIf));
            {
                // case: redeeming
                ops.append(&mut vec![
                    Push(vec![8]),  // (=payment amount size)
                    Code(OpNum2Bin),
                    Code(OpFromAltStack),
                    Code(OpHash160),
                    Code(OpSwap),
                    Code(OpCat),
                    Code(OpFromAltStack),
                    Code(OpCat),
                    Code(OpFromAltStack),
                    Code(OpCheckDataSigVerify),
                    Push(self.lokad_id.clone()),
                    Code(OpEqual),
                ]);
            }
            ops.push(Code(OpElse));
            {
                // case: refilling
                ops.append(&mut vec![
                    Code(Op2Drop),
                ]);
            }
            ops.push(Code(OpEndIf));
        }
        ops.push(Code(OpElse));
        {
            // case p2pk
            ops.append(&mut vec![
                Code(OpNip),
                Code(OpCheckSig),
            ]);
        }
        ops.push(Code(OpEndIf));

        ops
    }
}

impl Output for P2AscendingNonce {
    fn value(&self) -> u64 {
        self.old_value
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
        use self::P2AscendingNonceSpendParams::*;
        let spend_params = self.spend_params.as_ref().expect("must provide spend params!");
        match spend_params {
            NonceRedeem { .. } | NonceRefill { .. } => {
                let (payment_amount, new_nonce, owner_sig, is_terminal) = match spend_params {
                    NonceRedeem { payment_amount, new_nonce, owner_sig, is_terminal } => {
                        (*payment_amount, *new_nonce, owner_sig.clone(), *is_terminal)
                    },
                    NonceRefill { payment_amount } => {
                        (*payment_amount, self.old_nonce, vec![], false)
                    },
                    P2pk => unreachable!(),
                };
                serialized_sig.remove(serialized_sig.len() - 1);  // remove sig flag
                let script_code = self.script_code().to_vec_sig();
                let nonce_size = 9;  // len("PUSH <oldNonce>")
                let pk_size = 34;  // len("PUSH <pubkey>")
                Script::new(vec![
                    Op::Push(self.lokad_id.clone()),
                    Op::Push(owner_sig.clone()),  // ownerDataSig
                    Op::Push({  // outputsPost
                        let mut outputs_post = Vec::new();
                        outputs[if is_terminal { 0 } else { 1 }..].iter()
                            .for_each(|tx_output| {
                                tx_output.write_to_stream(&mut outputs_post).unwrap()
                            });
                        outputs_post
                    }),
                    Op::Push(serialized_pub_key),  // covenantPk
                    Op::Push(serialized_sig),  // covenantDataSig
                    Op::Push({  // preimagePrefix
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
                        pre_image_part.extend_from_slice(&script_code[..nonce_size]);
                        pre_image_part
                    }),
                    Op::Push({  // preimageSuffix
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
                    Op::Push(encode_int(payment_amount)),
                    Op::Push(encode_int(self.old_value.try_into().unwrap())),
                    Op::Push(script_code[nonce_size..][..pk_size].to_vec()),
                    Op::Push(script_code[nonce_size..][pk_size..].to_vec()),
                    Op::Push(encode_int(new_nonce)),
                    Op::Push(vec![1]),
                ])
            },
            P2pk => {
                Script::new(vec![
                    Op::Push(serialized_sig),
                    Op::Push(encode_int(0)),
                ])
            },
        }
    }
}
