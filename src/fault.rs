#[derive(Clone, Copy, Debug)]
/// Representation of different types of faults
pub enum FaultType {
    /// A fault which skips `n` instructions
    Glitch(usize),
}

#[derive(Clone, Copy, Debug)]
/// Representation for a fault which shall be executed at step `index` of a simulation.
pub struct SimulationFaultRecord {
    pub index: usize,
    pub fault_type: FaultType,
}

impl SimulationFaultRecord {
    pub fn new(index: usize, fault_type: FaultType) -> SimulationFaultRecord {
        SimulationFaultRecord { index, fault_type }
    }
}

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
/// Representation of a single instruction executed during a simulation.
pub struct TracePoint {
    pub address: u64,
    pub asm_instruction: Vec<u8>,
    pub registers: Option<[u32; 17]>,
}

#[derive(Clone, Debug)]
/// Representation of an fault which was executed in a simulation
pub struct FaultData {
    /// The original instructions which would have been performed without the fault
    pub original_instructions: Vec<u8>,
    /// The execution trace of this fault
    pub record: TracePoint,
    /// SimulationFaultRecord which caused this FaultData to be simulated
    pub fault: SimulationFaultRecord,
}

impl FaultData {
    pub fn get_simulation_fault_records(
        fault_data_records: &[FaultData],
    ) -> Vec<SimulationFaultRecord> {
        fault_data_records
            .iter()
            .map(|record| record.fault)
            .collect()
    }
}
