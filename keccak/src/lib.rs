use ethers_core::types::U256 as EthU256;

use serde::{Serialize, Serializer};
use serde_json::from_reader;
use serde_tuple::*;

use zokrates_abi::{parse_strict, parse_value, Encode, Inputs};
use zokrates_ark::Ark;
use zokrates_ast::ir::{self, ProgEnum, Witness};
use zokrates_ast::typed::abi::Abi;
use zokrates_bellperson::nova;
use zokrates_field::{Bn128Field, PallasField};
use zokrates_proof_systems::*;

use rand_0_8::rngs::StdRng;
use rand_0_8::SeedableRng;

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::Instant;

const SEQ_LEN: usize = 2;

#[derive(Serialize, Default, Clone, Debug)]
pub struct State {
    idx: U8Wrapper,
    outputs: [U256; SEQ_LEN], // TODO this is the sequence length
}

#[derive(Default, Copy, Clone, Debug)]
struct U8Wrapper(pub u8);

impl Serialize for U8Wrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

#[derive(Serialize, Default, Copy, Clone, Debug)]
pub struct U256 {
    limbs: [U8Wrapper; 32],
}

impl From<u128> for U256 {
    fn from(x: u128) -> Self {
        let y: EthU256 = x.into();
        y.into()
    }
}

impl From<EthU256> for U256 {
    fn from(x: EthU256) -> Self {
        let mut bytes: [u8; 32] = [0; 32];
        x.to_big_endian(&mut bytes);
        let v_bytes: Vec<_> = bytes.into_iter().map(U8Wrapper).collect();
        Self {
            limbs: v_bytes.try_into().unwrap(),
        }
    }
}

#[derive(Serialize, Clone, Copy, Debug)]
pub struct HashInputs {
    words: [U256; 2],
}

impl HashInputs {
    pub fn new(x: EthU256, y: EthU256) -> Self {
        Self {
            words: [x.into(), y.into()],
        }
    }
}

#[derive(Serialize_tuple, Clone, Copy, Debug)]
pub struct CircuitInputGroth16 {
    w: HashInputs,
}

impl CircuitInputGroth16 {
    pub fn new(w: HashInputs) -> Self {
        Self { w }
    }
}

pub struct Prover;

impl Prover {
    pub fn prove_nova(hash_input_seq: &[HashInputs; SEQ_LEN], dir: String) -> Result<(), String> {
        let circuit_file = format!("{dir}/out");
        let path = Path::new(&circuit_file);
        let file = File::open(path)
            .map_err(|why| format!("Could not open {}: {}", path.display(), why))?;

        let mut reader = BufReader::new(file);

        let prog = match ProgEnum::deserialize(&mut reader).unwrap() {
            ProgEnum::PallasProgram(p) => p,
            _ => panic!(),
        };
        let prog = prog.collect();

        let abi_file = format!("{dir}/abi.json");
        let path = Path::new(&abi_file);
        let file = File::open(path)
            .map_err(|why| format!("Could not open {}: {}", path.display(), why))?;
        let mut reader = BufReader::new(file);

        let abi: Abi = from_reader(&mut reader).map_err(|why| why.to_string())?;

        let signature = abi.signature();

        let init_type = signature.inputs[0].clone();
        let step_type = signature.inputs[1].clone();

        println!("Encoding initial state...");
        let init = parse_value::<PallasField>(
            serde_json::from_str(&serde_json::to_string(&State::default()).unwrap()).unwrap(),
            init_type,
        )
        .unwrap()
        .encode();

        println!("Encoding witness list...");
        let steps: Vec<_> = hash_input_seq
            .iter()
            .map(|h| {
                parse_value::<PallasField>(
                    serde_json::from_str(&serde_json::to_string(h).unwrap()).unwrap(),
                    step_type.clone(),
                )
                .unwrap()
                .encode()
            })
            .collect();

        println!("Generating public parameters...");
        let start_pp = Instant::now();
        let params = nova::generate_public_parameters(prog.clone()).map_err(|e| e.to_string())?;
        let duration_pp = start_pp.elapsed();
        println!("Time spent in public parameters setup: {duration_pp:?}");

        println!("Proving...");
        let start_proof = Instant::now();
        let _proof = nova::prove(&params, prog, init, steps)
            .map_err(|e| format!("Error `{e:#?}` during proving"))?;
        let duration_proof = start_proof.elapsed();
        println!("Time spent in proving: {duration_proof:?}");

        //println!("{:?}", proof);

        Ok(())
    }

    pub fn prove_groth16(
        hash_input_seq: &[HashInputs; SEQ_LEN],
        dir: String,
    ) -> Result<(), String> {
        let circuit_file = format!("{dir}/out");
        let path = Path::new(&circuit_file);
        let file = File::open(path)
            .map_err(|why| format!("Could not open {}: {}", path.display(), why))?;

        let mut reader = BufReader::new(file);

        let prog = match ProgEnum::deserialize(&mut reader).unwrap() {
            ProgEnum::Bn128Program(p) => p,
            _ => panic!(),
        };
        let prog = prog.collect();

        let pk_file = format!("{dir}/proving.key");
        let pk_path = Path::new(&pk_file);
        let pk_file = File::open(pk_path)
            .map_err(|why| format!("Could not open {}: {}", pk_path.display(), why))?;

        let mut pk: Vec<u8> = Vec::new();
        let mut pk_reader = BufReader::new(pk_file);
        pk_reader
            .read_to_end(&mut pk)
            .map_err(|why| format!("Could not read {}: {}", pk_path.display(), why))?;

        let mut rng = StdRng::from_entropy();

        hash_input_seq.iter().for_each(|h| {
            let witness =
                Self::compute_witness_bn128(prog.clone(), CircuitInputGroth16::new(*h), &dir)
                    .unwrap();

            let start_proof = Instant::now();
            let proof: Proof<Bn128Field, G16> =
                Ark::generate_proof(prog.clone(), witness, pk.clone(), &mut rng);
            let duration_proof = start_proof.elapsed();
            println!("Time spent proving (Groth16): {duration_proof:?}");

            let _proof = serde_json::to_string_pretty(&TaggedProof::<Bn128Field, G16>::new(
                proof.proof,
                proof.inputs,
            ))
            .unwrap();

            //println!("Proof:\n{proof}");
        });

        //Ok(ret)
        Ok(())
    }

    fn compute_witness_bn128<'a, I: IntoIterator<Item = ir::Statement<'a, Bn128Field>>>(
        prog: ir::ProgIterator<'a, Bn128Field, I>,
        inputs: CircuitInputGroth16,
        dir: &String,
    ) -> Result<Witness<Bn128Field>, String> {
        let signature = {
            let abi_file = format!("{dir}/abi.json");
            let path = Path::new(&abi_file);
            let file = File::open(path)
                .map_err(|why| format!("Could not open {}: {}", path.display(), why))?;
            let mut reader = BufReader::new(file);

            let abi: Abi = from_reader(&mut reader).map_err(|why| why.to_string())?;

            abi.signature()
        };

        let arguments = parse_strict(
            serde_json::to_string(&inputs).unwrap().as_str(),
            signature.inputs,
        )
        .map(Inputs::Abi)
        .map_err(|why| why.to_string())
        .map_err(|e| format!("Could not parse argument: {e}"))?;

        let interpreter = zokrates_interpreter::Interpreter::default();

        let _public_inputs = prog.public_inputs();

        let encoded = arguments.encode();
        let witness = interpreter
            .execute_with_log_stream(prog, &encoded, &mut std::io::stdout())
            .map_err(|e| format!("Execution failed: {e}"))?;

        // Uncomment to see the witness verification result values
        /*
        use zokrates_abi::Decode;

        let results_json_value: serde_json::Value =
            zokrates_abi::Value::decode(witness.return_values(), *signature.output)
                .into_serde_json();

        println!("\nWitness: \n{results_json_value}\n");
        */

        Ok(witness)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn nova() {
        let hash_inputs = [HashInputs::new(1.into(), 2.into()); SEQ_LEN];

        Prover::prove_nova(&hash_inputs, "../circuits/keccak_nova".to_string()).unwrap();
    }

    #[test]
    fn groth16() {
        let hash_inputs = [HashInputs::new(1.into(), 2.into()); SEQ_LEN];

        Prover::prove_groth16(&hash_inputs, "../circuits/keccak_groth16".to_string()).unwrap();
    }
}
