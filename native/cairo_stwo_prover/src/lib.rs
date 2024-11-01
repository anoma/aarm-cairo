mod errors;

use std::collections::BTreeMap;
pub use stwo_cairo_prover::input::{
    CairoInput,
    SegmentAddrs,
    instructions::{Instructions, VmState},
    mem::{Memory, MemoryBuilder, MemConfig},
    range_check_unit::RangeCheckUnitInput,
    vm_import::{TraceEntry, MemEntry},
};
pub use stwo_cairo_prover::cairo_air::{prove_cairo, verify_cairo};

use crate::errors::StwoProveError;
use bytemuck::cast_slice;
use rustler::{Error, NifResult};

#[rustler::nif(schedule = "DirtyCpu")]
pub fn cairo_stwo_prove(
    trace: Vec<u8>,
    memory: Vec<u8>,
    public_input: Vec<u8>,
) -> NifResult<(Vec<u8>, Vec<u8>)> {
    // Parse public input to get memory segments and public memory entries
    let pub_data = parse_public_input(&public_input).unwrap();
    let end_addr = pub_data.memory_segments
        .values()
        .map(|v| v.stop_ptr)
        .max()
        .expect("No memory segments found");
    assert!(end_addr < (1 << 32));

    let mut trace_entries = trace
        .chunks_exact(24)
        .map(|chunk| {
            let ap = u64::from_le_bytes(chunk[0..8].try_into().map_err(|e| {
                Error::Term(Box::new(StwoProveError::TraceParseError(format!(
                    "Failed to parse AP: {:?}",
                    e
                ))))
            })?);
            let fp = u64::from_le_bytes(chunk[8..16].try_into().map_err(|e| {
                Error::Term(Box::new(StwoProveError::TraceParseError(format!(
                    "Failed to parse FP: {:?}",
                    e
                ))))
            })?);
            let pc = u64::from_le_bytes(chunk[16..24].try_into().map_err(|e| {
                Error::Term(Box::new(StwoProveError::TraceParseError(format!(
                    "Failed to parse PC: {:?}",
                    e
                ))))
            })?);
            Ok::<_, Error>(TraceEntry { ap, fp, pc })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let trace = trace_entries.iter().map(|t| (*t).into());

    // Parse memory entries
    let memory_entries = memory
        .chunks_exact(40)
        .enumerate()
        .filter_map(|(idx, chunk)| {
            let addr = u64::from_le_bytes(chunk[0..8].try_into().ok()?);
            let value: [u32; 8] = cast_slice(&chunk[8..40]).try_into().ok()?;
            Some(MemEntry { addr, val: value })
        });

    // Create memory config matching the original
    let mem_config = MemConfig::new((1 << 20) - 1, end_addr as u32);
    let mut range_check9 = RangeCheckUnitInput::new();
    let mut mem = MemoryBuilder::from_iter(mem_config, memory_entries);

    let instructions = Instructions::from_iter(trace, &mut mem);

    // Extract public memory addresses from public memory entries
    let public_mem_addresses = pub_data
        .public_memory
        .iter()
        .map(|entry| entry.address as u32)
        .collect();

    // Create CairoInput
    let cairo_input = CairoInput {
        instructions,
        mem: mem.build(),
        public_mem_addresses,
        range_check_builtin: SegmentAddrs {
            begin_addr: pub_data.memory_segments["range_check"].begin_addr as u32,
            end_addr: pub_data.memory_segments["range_check"].stop_ptr as u32,
        },
    };

    // Generate proof
    let proof = prove_cairo(cairo_input).map_err(|e| {
        Error::Term(Box::new(StwoProveError::ProofGenerationError(format!(
            "{:?}",
            e
        ))))
    })?;

    // Encode proof and pub_inputs
    let proof_bytes = bincode::serde::encode_to_vec(proof, bincode::config::standard()).map_err(|e| {
        Error::Term(Box::new(StwoProveError::EncodingError(format!(
            "Failed to encode proof: {:?}",
            e
        ))))
    })?;

    let pub_input_bytes = bincode::serde::encode_to_vec(&public_input, bincode::config::standard())
        .map_err(|e| {
            Error::Term(Box::new(StwoProveError::EncodingError(format!(
                "Failed to encode public input: {:?}",
                e
            ))))
        })?;

    Ok((proof_bytes, pub_input_bytes))
}

fn parse_public_input(input: &[u8]) -> Result<PublicInput, std::io::Error> {
    let mut offset = 0;

    // Parse rc_min and rc_max
    let rc_min = u16::from_le_bytes(
        input[offset..offset + 2]
            .try_into()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid length for rc_min"))?
    ) as u64;
    offset += 2;

    let rc_max = u16::from_le_bytes(
        input[offset..offset + 2]
            .try_into()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid length for rc_max"))?
    ) as u64;
    offset += 2;

    // Parse number of public memory entries
    let n_pub_mem = u64::from_le_bytes(
        input[offset..offset + 8]
            .try_into()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid length for n_pub_mem"))?
    );
    offset += 8;

    // Parse public memory entries
    let mut public_memory = Vec::with_capacity(n_pub_mem as usize);
    for _ in 0..n_pub_mem {
        let address = u64::from_le_bytes(
            input[offset..offset + 8]
                .try_into()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid length for address"))?
        );
        offset += 8;

        let mut value = [0u8; 32];
        value.copy_from_slice(&input[offset..offset + 32]);
        offset += 32;

        public_memory.push(PublicMemEntry {
            address,
            value: FeltValue(value),
            page: 0,
        });
    }

    // Parse memory segments
    let n_segments = input[offset] as usize;
    offset += 1;

    let mut memory_segments = BTreeMap::new();
    for _ in 0..n_segments {
        let segment_type = input[offset];
        offset += 1;

        let name = match segment_type {
            0 => "range_check",
            1 => "output",
            2 => "program",
            3 => "execution",
            4 => "ecdsa",
            5 => "pedersen",
            _ => "unknown",
        };

        let begin_addr = u64::from_le_bytes(
            input[offset..offset + 8]
                .try_into()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid length for begin_addr"))?
        );
        offset += 8;

        let stop_ptr = u64::from_le_bytes(
            input[offset..offset + 8]
                .try_into()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid length for stop_ptr"))?
        );
        offset += 8;

        memory_segments.insert(name.to_string(), Segment { begin_addr, stop_ptr });
    }

    // Create and return PublicInput struct
    Ok(PublicInput {
        layout: "plain".to_string(),
        rc_min,
        rc_max,
        n_steps: n_pub_mem,
        memory_segments,
        public_memory,
        dynamic_params: None,
    })
}

#[derive(Clone, Debug)]
pub struct Segment {
    pub begin_addr: u64,
    pub stop_ptr: u64,
}

#[derive(Clone, Debug)]
pub struct PublicMemEntry {
    pub address: u64,
    pub value: FeltValue,
    pub page: u64,
}

#[derive(Clone, Debug)]
pub struct FeltValue([u8; 32]);

#[derive(Clone, Debug)]
pub struct PublicInput {
    pub layout: String,
    pub rc_min: u64,
    pub rc_max: u64,
    pub n_steps: u64,
    pub memory_segments: BTreeMap<String, Segment>,
    pub public_memory: Vec<PublicMemEntry>,
    pub dynamic_params: Option<()>,
}

rustler::init!("Elixir.Cairo.CairoStwoProver", [cairo_stwo_prove]);