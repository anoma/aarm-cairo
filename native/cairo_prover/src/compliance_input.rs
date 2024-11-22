use crate::{error::CairoError, utils::felt_to_string};
use rustler::NifResult;
use serde::{Deserialize, Serialize};

#[rustler::nif]
fn cairo_generate_compliance_input_json(
    input_resource: Vec<u8>,
    output_resource: Vec<u8>,
    path: Vec<Vec<u8>>,
    pos: u64,
    input_nf_key: Vec<u8>,
    eph_root: Vec<u8>,
    rcv: Vec<u8>,
) -> NifResult<String> {
    Ok(ComplianceInputJson::to_json_string(
        input_resource,
        output_resource,
        path,
        pos,
        input_nf_key,
        eph_root,
        rcv,
    )?)
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ComplianceInputJson {
    input: ResourceJson,
    output: ResourceJson,
    input_nf_key: String,
    merkle_path: Vec<PathNode>,
    rcv: String,
    eph_root: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct ResourceJson {
    logic: String,
    label: String,
    quantity: String,
    data: String,
    eph: bool,
    nonce: String,
    npk: String,
    rseed: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct PathNode {
    fst: String,
    snd: bool,
}

impl ComplianceInputJson {
    pub fn to_json_string(
        input_resource: Vec<u8>,
        output_resource: Vec<u8>,
        path: Vec<Vec<u8>>,
        pos: u64,
        input_nf_key: Vec<u8>,
        eph_root: Vec<u8>,
        rcv: Vec<u8>,
    ) -> Result<String, CairoError> {
        let input = ResourceJson::from_bytes(input_resource)?;
        let output = ResourceJson::from_bytes(output_resource)?;

        let rcv = felt_to_string(rcv)?;
        let eph_root = felt_to_string(eph_root)?;
        let input_nf_key = felt_to_string(input_nf_key)?;
        let mut next_pos = pos;
        let mut merkle_path = Vec::new();
        for node in path.into_iter() {
            let snd = next_pos % 2 != 0;
            next_pos >>= 1;
            let node = PathNode {
                fst: felt_to_string(node)?,
                snd,
            };
            merkle_path.push(node);
        }

        let compliance_input = Self {
            input,
            output,
            input_nf_key,
            merkle_path,
            rcv,
            eph_root,
        };
        Ok(serde_json::to_string(&compliance_input)?)
    }
}

impl ResourceJson {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CairoError> {
        Ok(Self {
            logic: felt_to_string(bytes[0..32].to_vec())?,
            label: felt_to_string(bytes[32..64].to_vec())?,
            quantity: felt_to_string(bytes[64..96].to_vec())?,
            data: felt_to_string(bytes[96..128].to_vec())?,
            nonce: felt_to_string(bytes[128..160].to_vec())?,
            npk: felt_to_string(bytes[160..192].to_vec())?,
            rseed: felt_to_string(bytes[192..224].to_vec())?,
            eph: bytes[224] != 0,
        })
    }
}

#[test]
fn test_compliance_input_json() {
    use crate::utils::random_felt;
    use rand::{thread_rng, RngCore};

    let mut rng = thread_rng();
    let mut random_resouce = [0u8; 225];
    rng.fill_bytes(&mut random_resouce);

    let path = (0..32).map(|_| random_felt()).collect();

    let json = ComplianceInputJson::to_json_string(
        random_resouce.to_vec(),
        random_resouce.to_vec(),
        path,
        0,
        random_felt(),
        random_felt(),
        random_felt(),
    )
    .unwrap();

    println!("compliance_input_json: {}", json);
}

#[test]
fn generate_compliance_input_test_params() {
    use starknet_crypto::poseidon_hash;
    use starknet_types_core::felt::Felt;

    println!("Felf one hex: {:?}", Felt::ONE.to_hex_string());
    let input_nf_key = Felt::ONE;
    let input_npk = poseidon_hash(input_nf_key, Felt::ZERO);
    println!("input_npk: {:?}", input_npk.to_bytes_be());
    println!("input_npk: {:?}", input_npk.to_hex_string());
}
