use addr2line::{fallible_iterator::FallibleIterator, gimli};
use capstone::prelude::*;

use crate::fault::{FaultData, TracePoint};

pub struct Disassembly {
    cs: Capstone,
}

impl Disassembly {
    pub fn new() -> Self {
        let cs = Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Thumb)
            .extra_mode([arch::arm::ArchExtraMode::MClass].iter().copied())
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");

        Self { cs }
    }

    fn disassemble_fault_data(&self, fault_data: &FaultData) {
        let insns_data = self
            .cs
            .disasm_all(&fault_data.original_instructions, fault_data.record.address)
            .expect("Failed to disassemble");
        let insns_data_changed = self
            .cs
            .disasm_all(
                &fault_data.record.asm_instruction,
                fault_data.record.address,
            )
            .expect("Failed to disassemble");

        for (ins, ins_changed) in insns_data.iter().zip(insns_data_changed.iter()) {
            println!(
                "0x{:X}:  {} {} -> {} {}",
                ins.address(),
                ins.mnemonic().unwrap(),
                ins.op_str().unwrap(),
                ins_changed.mnemonic().unwrap(),
                ins_changed.op_str().unwrap()
            );
        }
    }

    fn disassemble_trace_point(&self, trace_record: &TracePoint) {
        let insns_data = self
            .cs
            .disasm_all(&trace_record.asm_instruction, trace_record.address)
            .expect("Failed to disassemble");

        for ins in insns_data.iter() {
            print!(
                "0x{:X}:  {:6} {:40}     < ",
                ins.address(),
                ins.mnemonic().unwrap(),
                ins.op_str().unwrap(),
            );
            if let Some(registers) = &trace_record.registers {
                let reg_list: [usize; 9] = [16, 0, 1, 2, 3, 4, 5, 6, 7];

                reg_list.iter().for_each(|index| {
                    if *index == 16 {
                        let cpsr = registers[*index];
                        let flag_n = (cpsr & 0x80000000) >> 31;
                        let flag_z = (cpsr & 0x40000000) >> 30;
                        let flag_c = (cpsr & 0x20000000) >> 29;
                        let flag_v = (cpsr & 0x10000000) >> 28;
                        print!("NZCV:{}{}{}{} ", flag_n, flag_z, flag_c, flag_v);
                    } else {
                        print!("R{}=0x{:08X} ", index, registers[*index]);
                    }
                });
            }
            println!(">");
        }
    }

    /// Print fault data of given fault_data_vec vector
    pub fn print_fault_records(
        &self,
        fault_data_vec: &Option<Vec<Vec<FaultData>>>,
        debug_context: &addr2line::Context<
            gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>,
        >,
    ) {
        if let Some(fault_data_vec) = fault_data_vec {
            fault_data_vec
                .iter()
                .enumerate()
                .for_each(|(attack_num, fault_context)| {
                    println!("Attack number {}", attack_num + 1);
                    fault_context.iter().for_each(|fault_data| {
                        self.disassemble_fault_data(fault_data);
                        self.print_debug_info(fault_data.record.address, debug_context);
                        println!();
                    });
                    println!("------------------------");
                });
        }
    }

    fn print_debug_info(
        &self,
        address: u64,
        debug_context: &addr2line::Context<
            gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>,
        >,
    ) {
        if let Ok(frames) = debug_context.find_frames(address).skip_all_loads() {
            for frame in frames.iterator().flatten() {
                if let Some(location) = frame.location {
                    match (location.file, location.line) {
                        (Some(file), Some(line)) => {
                            println!("\t\t{:?}:{:?}", file, line)
                        }

                        (Some(file), None) => println!("\t\t{:?}", file),
                        _ => println!("No debug info available"),
                    }
                }
            }
        }
    }

    /// Print trace_record of given trace_records vector
    pub fn print_trace_records(&self, trace_records: &[TracePoint]) {
        trace_records.iter().for_each(|trace_record| {
            self.disassemble_trace_point(trace_record);
        });
        println!("------------------------");
    }
}
