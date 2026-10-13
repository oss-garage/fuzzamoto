use crate::{
    Instruction, Operation, PerTestcaseMetadata, Variable,
    generators::{Generator, GeneratorResult, ProgramBuilder},
};
use rand::{Rng, RngCore};

#[derive(Debug, Clone, Copy)]
enum ConnectionType {
    Inbound,
    Outbound,
    OutboundReconciliation,
}

impl ConnectionType {
    fn as_str(self) -> &'static str {
        match self {
            ConnectionType::Inbound => "inbound",
            ConnectionType::Outbound => "outbound",
            ConnectionType::OutboundReconciliation => "outbound-full-recon",
        }
    }
}

/// `AddConnectionGenerator` generates programs that create new connections to a node
///
/// Can be configured to:
/// - Perform handshake or not
/// - Create inbound or outbound connections
pub struct AddConnectionGenerator {
    handshake: bool,
    connection_type: ConnectionType,
}

impl AddConnectionGenerator {
    #[must_use]
    pub fn handshake_outbound() -> Self {
        Self {
            handshake: true,
            connection_type: ConnectionType::Outbound,
        }
    }

    #[must_use]
    pub fn handshake_inbound() -> Self {
        Self {
            handshake: true,
            connection_type: ConnectionType::Inbound,
        }
    }

    #[must_use]
    pub fn handshake_outbound_reconciliation() -> Self {
        Self {
            handshake: true,
            connection_type: ConnectionType::OutboundReconciliation,
        }
    }

    #[must_use]
    pub fn outbound() -> Self {
        Self {
            handshake: false,
            connection_type: ConnectionType::Outbound,
        }
    }

    #[must_use]
    pub fn inbound() -> Self {
        Self {
            handshake: false,
            connection_type: ConnectionType::Inbound,
        }
    }
}

impl<R: RngCore> Generator<R> for AddConnectionGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        // Handshake connections are slower, so add fewer per call to avoid timeouts.
        let num_connections = if self.handshake {
            rng.gen_range(1..=5)
        } else {
            rng.gen_range(1..=20)
        };

        for _ in 0..num_connections {
            let node_var = if let Some(v) = builder.get_random_variable(rng, &Variable::Node) {
                v
            } else {
                if builder.context().num_nodes == 0 {
                    return Err(crate::generators::GeneratorError::InvalidContext(
                        builder.context().clone(),
                    ));
                }

                builder
                    .append(Instruction {
                        inputs: vec![],
                        operation: Operation::LoadNode(
                            rng.gen_range(0..builder.context().num_nodes),
                        ),
                    })
                    .expect("Inserting LoadNode should always succeed")
                    .pop()
                    .expect("LoadNode should always produce a var")
            };

            let conn_type_var = builder
                .append(Instruction {
                    inputs: vec![],
                    operation: Operation::LoadConnectionType(
                        self.connection_type.as_str().to_string(),
                    ),
                })
                .expect("Inserting LoadConnectionType should always succeed")
                .pop()
                .expect("LoadConnectionType should always produce a var");

            if self.handshake {
                let reconciliation =
                    matches!(self.connection_type, ConnectionType::OutboundReconciliation);
                let handshake_opts_var = builder
                    .append(Instruction {
                        inputs: vec![],
                        operation: Operation::LoadHandshakeOpts {
                            relay: reconciliation || rng.gen_bool(0.5),
                            starting_height: rng.gen_range(0..400),
                            wtxidrelay: reconciliation || rng.gen_bool(0.5),
                            addrv2: rng.gen_bool(0.5),
                            erlay: reconciliation || rng.gen_bool(0.5),
                        },
                    })
                    .expect("Inserting LoadHandshakeOpts should always succeed")
                    .pop()
                    .expect("LoadHandshakeOpts should always produce a var");

                let time_var = match builder.get_random_variable(rng, &Variable::Time) {
                    Some(v) => v,
                    None => builder
                        .append(Instruction {
                            inputs: vec![],
                            operation: Operation::LoadTime(builder.context().timestamp),
                        })
                        .expect("Inserting LoadTime should always succeed")
                        .pop()
                        .expect("LoadTime should always produce a var"),
                };

                builder
                    .append(Instruction {
                        inputs: vec![
                            node_var.index,
                            conn_type_var.index,
                            handshake_opts_var.index,
                            time_var.index,
                        ],
                        operation: Operation::AddConnectionWithHandshake {
                            send_compact: if rng.gen_bool(0.8) {
                                Some(rng.gen_bool(0.5))
                            } else {
                                None
                            },
                        },
                    })
                    .expect("Inserting AddConnectionWithHandshake should always succeed");
            } else {
                builder
                    .append(Instruction {
                        inputs: vec![node_var.index, conn_type_var.index],
                        operation: Operation::AddConnection,
                    })
                    .expect("Inserting AddConnection should always succeed");
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        match (self.handshake, self.connection_type) {
            (true, ConnectionType::Outbound) => "AddConnectionGenerator:out:handshake",
            (true, ConnectionType::Inbound) => "AddConnectionGenerator:in:handshake",
            (true, ConnectionType::OutboundReconciliation) => {
                "AddConnectionGenerator:out-recon:handshake"
            }
            (false, ConnectionType::Outbound) => "AddConnectionGenerator:out",
            (false, ConnectionType::Inbound) => "AddConnectionGenerator:in",
            (false, ConnectionType::OutboundReconciliation) => {
                unreachable!("Only handshaken reconciliation connections are generated")
            }
        }
    }
}
