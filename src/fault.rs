use std::fmt;

#[derive(Clone, Copy, Debug)]
pub enum FaultType {
    /// A fault which skips `n` instructions
    Glitch(usize),
}

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct TracePoint {
    pub address: u64,
    pub instruction_size: usize,
    pub asm_instruction: Vec<u8>,
    pub registers: Option<[u32; 17]>,
}

impl TracePoint {
    pub fn get_fault_record(&self, index: usize, fault_type: FaultType) -> SimulationFaultRecord {
        SimulationFaultRecord {
            index,
            record: self.clone(),
            fault_type,
        }
    }
}

#[derive(Clone)]
pub struct SimulationFaultRecord {
    pub index: usize,
    pub record: TracePoint,
    pub fault_type: FaultType,
}

impl fmt::Debug for SimulationFaultRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "address: 0x{:X} size: 0x{:?} fault_type: {:?}",
            self.record.address, self.record.instruction_size, self.fault_type
        )
    }
}

#[derive(Clone, Debug)]
pub struct FaultData {
    pub original_instructions: Vec<u8>,
    pub manipulated_instructions: Vec<u8>,
    pub fault: SimulationFaultRecord,
}

impl FaultData {
    pub fn get_simulation_fault_records(
        fault_data_records: &[FaultData],
    ) -> Vec<SimulationFaultRecord> {
        fault_data_records
            .iter()
            .map(|record| record.fault.clone())
            .collect()
    }
}
