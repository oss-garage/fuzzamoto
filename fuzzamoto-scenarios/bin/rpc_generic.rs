use fuzzamoto::{
    fuzzamoto_main,
    runners::Runner,
    scenarios::{Scenario, ScenarioInput, ScenarioResult},
    targets::{BitcoinCoreTarget, TargetNode},
};

use arbitrary::{Arbitrary, Unstructured};

use std::{collections::HashMap, fs};

#[derive(Arbitrary)]
enum ParamSource<T> {
    Fuzzer(T),
    Pool(u16),
}

#[derive(Arbitrary)]
enum RpcParam {
    Base64(ParamSource<Vec<u8>>),
    Hex(ParamSource<Vec<u8>>),
    String(ParamSource<String>),
    Number(ParamSource<u64>),
    Boolean(ParamSource<bool>),
    Array(ParamSource<Vec<RpcParam>>),
}

#[derive(Arbitrary)]
struct CallRpc {
    name: u16,
    params: Vec<RpcParam>,
}

#[derive(Arbitrary)]
struct TestCase {
    rpc_calls: Vec<CallRpc>,
}

impl ScenarioInput<'_> for TestCase {
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut unstructured = Unstructured::new(bytes);
        let rpc_calls = Vec::arbitrary(&mut unstructured).map_err(|e| e.to_string())?;
        Ok(Self { rpc_calls })
    }
}

struct RpcParamPool {
    params: HashMap<&'static str, Vec<serde_json::Value>>,
}

impl RpcParamPool {
    fn new() -> Self {
        Self {
            params: HashMap::new(),
        }
    }

    fn param_key(param: &RpcParam) -> &'static str {
        match param {
            RpcParam::Boolean(_) => "bool",
            RpcParam::Number(_) => "number",
            RpcParam::Hex(_) => "hex",
            RpcParam::Base64(_) => "base64",
            RpcParam::String(_) => "string",
            RpcParam::Array(_) => "array",
        }
    }

    fn param_key_from_json_key(key: &str) -> Option<&'static str> {
        match key {
            "txid" | "wtxid" | "hash" | "blockhash" | "hex" => Some("hex"),
            _ => None,
        }
    }

    fn add(&mut self, key: &'static str, param: serde_json::Value) {
        self.params.entry(key).or_default().push(param);
    }

    fn add_rpc_result(&mut self, result: serde_json::Value) {
        if result.is_number() {
            self.add("number", result);
        } else if result.is_string() {
            self.add("string", result);
        } else if result.is_boolean() {
            self.add("bool", result);
        } else if result.is_array() {
            self.add("array", result.clone());
            for item in result.as_array().unwrap() {
                self.add_rpc_result(item.clone());
            }
        } else if result.is_object() {
            for (key, value) in result.as_object().unwrap() {
                if let Some(key) = Self::param_key_from_json_key(key) {
                    self.add(key, value.clone());
                } else {
                    self.add_rpc_result(value.clone());
                }
            }
        }
    }

    fn get(&self, param: &RpcParam, index: u16) -> Option<serde_json::Value> {
        let pool_params = self.params.get(Self::param_key(param))?;

        let pool_size = pool_params.len();
        if pool_size == 0 {
            return None;
        }

        Some(pool_params[index as usize % pool_size].clone())
    }

    fn get_json_params_from_pool(
        &mut self,
        param: &RpcParam,
        json_params: &mut Vec<serde_json::Value>,
    ) {
        match param {
            RpcParam::Boolean(ParamSource::Pool(pool_index))
            | RpcParam::Number(ParamSource::Pool(pool_index))
            | RpcParam::Hex(ParamSource::Pool(pool_index))
            | RpcParam::Base64(ParamSource::Pool(pool_index))
            | RpcParam::String(ParamSource::Pool(pool_index))
            | RpcParam::Array(ParamSource::Pool(pool_index)) => {
                if let Some(param) = self.get(param, *pool_index) {
                    json_params.push(param);
                }
            }
            _ => {}
        }
    }

    fn get_json_params_inner(
        &mut self,
        params: &[RpcParam],
        json_params: &mut Vec<serde_json::Value>,
    ) {
        use base64::prelude::*;
        for rpc_param in params {
            match rpc_param {
                RpcParam::Boolean(ParamSource::Fuzzer(b)) => json_params.push((*b).into()),
                RpcParam::Number(ParamSource::Fuzzer(n)) => json_params.push((*n).into()),
                RpcParam::Hex(ParamSource::Fuzzer(h)) => json_params.push(hex::encode(h).into()),
                RpcParam::Base64(ParamSource::Fuzzer(b)) => {
                    json_params.push(BASE64_STANDARD.encode(b).into());
                }
                RpcParam::String(ParamSource::Fuzzer(s)) => json_params.push(s.clone().into()),
                RpcParam::Array(ParamSource::Fuzzer(a)) => {
                    self.get_json_params_inner(a, json_params);
                }
                param => self.get_json_params_from_pool(param, json_params),
            }
        }
    }

    fn get_json_params(&mut self, params: &[RpcParam]) -> Vec<serde_json::Value> {
        let mut json_params = Vec::<serde_json::Value>::new();
        self.get_json_params_inner(params, &mut json_params);
        json_params
    }
}

/// `RpcScenario` is a scenario that tests the RPC interface of Bitcoin Core.
///
/// Testcases simulate the processing of a series of RPCs by the Bitcoin Core node. Each RPC is
/// given parameters either from the fuzz input or from the `RpcParamPool` (collection of params
/// returned by previously called RPCs).
struct RpcScenario {
    target: BitcoinCoreTarget,
    param_pool: RpcParamPool,

    available_rpcs: Vec<String>,
}

impl Scenario<'_, TestCase> for RpcScenario {
    fn new(args: &[String]) -> Result<Self, String> {
        let target = BitcoinCoreTarget::from_path(&args[1])?;
        let rpcs =
            fs::read_to_string(&args[2]).map_err(|e| format!("Failed to parse file: {e}"))?;

        // Note that any change in the file may invalidate existing seeds
        let mut available_rpcs: Vec<String> = vec![];
        for line in rpcs.lines() {
            let rpc = line.trim();
            if !rpc.is_empty() {
                available_rpcs.push(rpc.to_string());
            }
        }

        // Remove the default wallet, so the test may create it
        let _ = target
            .node
            .client
            .call::<serde_json::Value>("unloadwallet", &["default".into()]);
        let wallet_path = target
            .node
            .workdir()
            .join("regtest")
            .join("wallets")
            .join("default");
        let _ = std::fs::remove_dir_all(&wallet_path);

        log::debug!("{available_rpcs:?}");

        Ok(Self {
            target,
            param_pool: RpcParamPool::new(),
            available_rpcs,
        })
    }

    fn run(&mut self, input: TestCase, _runner: &dyn Runner) -> ScenarioResult {
        if self.available_rpcs.is_empty() {
            return ScenarioResult::Fail("File with the RPC commands is empty".to_string());
        }

        for rpc_call in input.rpc_calls {
            // Convert the rpc parameters given by the fuzzer into `serde_json::Value`s. This may
            // either result in params interpreted from the fuzz input or taken from the
            // `RpcParamPool` (collection of params returned by previous RPCs).
            let params = self.param_pool.get_json_params(&rpc_call.params);

            let rpc_count = self.available_rpcs.len();
            let rpc_name = &self.available_rpcs[rpc_call.name as usize % rpc_count];

            log::info!("{rpc_name} {params:?}");

            let Ok(result) = self
                .target
                .node
                .client
                .call::<serde_json::Value>(rpc_name, &params)
            else {
                log::info!("\t-> Error");
                continue;
            };

            log::info!("\t-> {result}");

            // Add result values to the `RpcParamPool`
            self.param_pool.add_rpc_result(result);
        }

        if let Err(e) = self.target.is_alive() {
            return ScenarioResult::Fail(format!("Target is not alive: {e}"));
        }

        ScenarioResult::Ok
    }
}
fuzzamoto_main!(RpcScenario, TestCase);
