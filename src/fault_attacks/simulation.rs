use crate::{
    fault::{FaultData, SimulationFaultRecord, TracePoint},
    FaultType,
};

use super::ElfFile;

mod callback;
use callback::*;

use log::debug;
use std::collections::HashSet;
use unicorn_engine::{
    uc_error, Arch, HookType, Mode, Permission, RegisterARM, Unicorn, SECOND_SCALE,
};

const MAX_INSTRUCTIONS: usize = 2000;
const STACK_BASE: u64 = 0x80100000;
const STACK_SIZE: usize = 0x10000;
const BOOT_STAGE: u64 = 0x32000000;
const AUTH_BASE: u64 = 0xAA01000;

const T1_RET: [u8; 2] = [0x70, 0x47]; // bx lr
const T1_NOP: [u8; 4] = [0x00, 0xBF, 0x00, 0xBF];

const ARM_REG: [RegisterARM; 17] = [
    RegisterARM::R0,
    RegisterARM::R1,
    RegisterARM::R2,
    RegisterARM::R3,
    RegisterARM::R4,
    RegisterARM::R5,
    RegisterARM::R6,
    RegisterARM::R7,
    RegisterARM::R8,
    RegisterARM::R9,
    RegisterARM::R10,
    RegisterARM::R11,
    RegisterARM::R12,
    RegisterARM::SP,
    RegisterARM::LR,
    RegisterARM::PC,
    RegisterARM::CPSR,
];

#[derive(PartialEq, Debug, Clone, Copy, Default)]
enum RunState {
    #[default]
    Init = 0,
    Success,
    Failed,
    Error,
}

#[derive(Default)]
struct EmulationData {
    state: RunState,
    tracing: bool,
    with_register_data: bool,
    negative_run: bool,
    deactivate_print: bool,
    trace_data: Vec<TracePoint>,
    fault_data: Vec<FaultData>,
}

pub struct Simulation<'a> {
    file_data: &'a ElfFile,
    emu: Unicorn<'a, EmulationData>,
    program_counter: u64,
}

impl<'a> Simulation<'a> {
    pub fn new(file_data: &'a ElfFile) -> Self {
        // Setup platform -> ARMv8-m.base
        let mut emu = Unicorn::new_with_data(
            Arch::ARM,
            Mode::LITTLE_ENDIAN | Mode::MCLASS,
            EmulationData::default(),
        )
        .expect("failed to initialize Unicorn instance");
        // Initial setup
        // Setup MMIO
        const MINIMUM_MEMORY_SIZE: usize = 0x1000;
        // Next boot stage mem
        emu.mem_map(
            0x32000000,
            MINIMUM_MEMORY_SIZE,
            Permission::READ | Permission::WRITE,
        )
        .expect("failed to map boot stage page");

        // Code
        let code_size = (file_data.program.len() + MINIMUM_MEMORY_SIZE) & 0xfffff000;
        emu.mem_map(file_data.program_header.p_paddr, code_size, Permission::ALL)
            .expect("failed to map code page");

        // Stack
        emu.mem_map(STACK_BASE, STACK_SIZE, Permission::READ | Permission::WRITE)
            .expect("failed to map stack page");

        // Auth success / failed trigger
        emu.mem_map(AUTH_BASE, MINIMUM_MEMORY_SIZE, Permission::WRITE)
            .expect("failed to map mmio replacement");

        // IO address space
        emu.mmio_map_wo(0x11000000, MINIMUM_MEMORY_SIZE, mmio_serial_write_callback)
            .expect("failed to map serial IO");

        // Setup breakpoints
        emu.add_code_hook(
            file_data.flash_load_img.st_value,
            file_data.flash_load_img.st_value + 1,
            hook_code_flash_load_img_callback,
        )
        .expect("failed to set flash_load_img code hook");

        emu.add_mem_hook(
            HookType::MEM_WRITE,
            AUTH_BASE,
            AUTH_BASE + 4,
            mmio_auth_write_callback,
        )
        .expect("failed to set memory hook");

        Self {
            file_data,
            emu,
            program_counter: 0,
        }
    }

    /// Get current state of simulation
    ///
    fn get_state(&self) -> RunState {
        self.emu.get_data().state
    }

    /// Check if code under investigation is working correct for
    /// positive and negative execution
    ///
    pub fn check_program(&mut self) {
        // Run simulation
        self.init_and_load(true);
        let ret_info = self.run_steps(MAX_INSTRUCTIONS);
        if ret_info == Ok(()) {
            debug!("Program stopped successful");
        } else {
            debug!("Program stopped with {:?}", ret_info);
        }
        assert_eq!(self.get_state(), RunState::Success);

        self.init_and_load(false);
        let ret_info = self.run_steps(MAX_INSTRUCTIONS);
        if ret_info == Ok(()) {
            debug!("Program stopped successful");
        } else {
            debug!("Program stopped with {:?}", ret_info);
        }
        assert_eq!(self.get_state(), RunState::Failed);
    }

    fn init_and_load(&mut self, run_successful: bool) {
        // Clear registers
        ARM_REG
            .iter()
            .for_each(|reg| self.emu.reg_write(*reg, 0x00).unwrap());

        // Setup registers
        self.emu
            .reg_write(RegisterARM::SP, STACK_BASE + STACK_SIZE as u64 - 4)
            .expect("failed to set register");

        // Write code to memory area
        self.emu
            .mem_write(
                self.file_data.program_header.p_paddr,
                &self.file_data.program,
            )
            .expect("failed to write file data");

        // set initial program start address
        self.program_counter = self.file_data.program_header.p_paddr;

        // Write wrong flash data to boot stage memory
        let boot_stage: [u8; 4] = [0xB8, 0x45, 0x85, 0xFD];
        self.emu
            .mem_write(BOOT_STAGE, &boot_stage)
            .expect("failed to write boot stage data");

        // Set run type
        self.emu.get_data_mut().negative_run = !run_successful;

        // Set global state to initialized
        self.emu.get_data_mut().state = RunState::Init;
    }

    /// Execute code on pc set in internal structure till cycles
    fn run_steps(&mut self, cycles: usize) -> Result<(), uc_error> {
        let end_address =
            self.file_data.program_header.p_paddr + self.file_data.program_header.p_filesz;

        // Start from last PC
        let ret_val = self.emu.emu_start(
            self.program_counter | 1,
            end_address | 1,
            SECOND_SCALE,
            cycles,
        );

        // Store new PC
        self.program_counter = self.emu.pc_read().unwrap();

        ret_val
    }

    /// Function to deactivate printf of c program to
    /// avoid unexpected output
    fn deactivate_printf_function(&mut self) {
        self.emu.get_data_mut().deactivate_print = true;
        self.emu
            .mem_write(self.file_data.serial_puts.st_value & 0xfffffffe, &T1_RET)
            .unwrap();
    }

    /// Record the program flow till the program ends on positive or negative program execution
    /// A vector array with the recorded addresses is returned
    pub fn record_code_trace(
        &mut self,
        full_trace: bool,
        low_complexity: bool,
        faults: Vec<SimulationFaultRecord>,
    ) -> &Vec<TracePoint> {
        // Initialize and load
        self.init_and_load(false);

        // Deactivate io print
        self.deactivate_printf_function();

        // Set hook with faults and run program
        self.emu
            .add_code_hook(
                self.file_data.program_header.p_paddr,
                self.file_data.program_header.p_memsz,
                tracing_callback,
            )
            .expect("failed to setup trace hook");

        // If full trace is required, switch on tracing from the beginning
        if full_trace {
            self.start_tracing();
            self.with_register_data();
        }

        // Get the first one, set it and start
        faults.into_iter().for_each(|fault| {
            let mut ret_val = Ok(());
            if fault.index != 0 {
                ret_val = self.run_steps(fault.index);
            }
            if ret_val.is_ok() {
                self.emulate_fault(&fault);
            }
        });

        // Start tracing
        self.start_tracing();

        // Run
        let _ret_val = self.run_steps(MAX_INSTRUCTIONS);

        self.emu.get_data_mut().fault_data.clear();

        if low_complexity {
            self.reduce_trace();
        }
        self.get_trace()
    }

    /// Execute loaded code with the given faults injected before code execution
    /// If code finishes with successful state, a vector array will be returned with the
    /// injected faults
    pub fn run_with_faults(&mut self, faults: &[&SimulationFaultRecord]) -> Option<Vec<FaultData>> {
        self.init_and_load(false);

        // Deactivate io print
        self.deactivate_printf_function();

        // Get the first one, set it and start
        if !faults.is_empty() {
            faults.iter().for_each(|fault| {
                let mut ret_val = Ok(());
                if fault.index != 0 {
                    ret_val = self.run_steps(fault.index);
                }
                if ret_val.is_ok() {
                    let fault_data = self.emulate_fault(fault);
                    self.emu.get_data_mut().fault_data.push(fault_data);
                }
            });

            if self.get_state() == RunState::Success {
                println!("Da scheint ein Fehler aufgetreten zu sein");
                return None;
            }

            // Run
            let _ret_val = self.run_steps(MAX_INSTRUCTIONS);
            // Check state
            if self.get_state() == RunState::Success {
                return Some(self.emu.get_data().fault_data.clone());
            }
        }

        None
    }

    fn get_asm_cmd_size(&self, address: u64) -> Option<usize> {
        let mut data: [u8; 2] = [0; 2];
        // Check for 32bit cmd (0b11101... 0b1111....)
        if self.emu.mem_read(address, &mut data).is_ok() {
            if (data[1] & 0xF8 == 0xE8) || (data[1] & 0xF0 == 0xF0) {
                return Some(4);
            }
            return Some(2);
        }
        None
    }

    fn start_tracing(&mut self) {
        self.emu.get_data_mut().tracing = true;
    }

    fn with_register_data(&mut self) {
        self.emu.get_data_mut().with_register_data = true;
    }

    /// Copy trace data to caller
    fn get_trace(&self) -> &Vec<TracePoint> {
        &self.emu.get_data().trace_data
    }

    /// Remove duplicates to speed up testing
    fn reduce_trace(&mut self) {
        let trace_data = &mut self.emu.get_data_mut().trace_data;
        let hash_set: HashSet<TracePoint> = HashSet::from_iter(trace_data.clone());
        *trace_data = Vec::from_iter(hash_set);
    }

    fn emulate_glitch(
        &mut self,
        number_of_nops: usize,
        fault: &SimulationFaultRecord,
    ) -> FaultData {
        let address = self.program_counter;
        let mut manipulated_instructions = Vec::new();
        let registers = if self.emu.get_data().with_register_data {
            let mut registers: [u32; 17] = [0; 17];
            ARM_REG.iter().enumerate().for_each(|(index, register)| {
                registers[index] = self.emu.reg_read(*register).unwrap() as u32;
            });
            Some(registers)
        } else {
            None
        };
        let mut nop_size = 0;
        for _count in 0..number_of_nops {
            let instruction_size = self.get_asm_cmd_size(address + nop_size).unwrap();
            manipulated_instructions.extend_from_slice(&T1_NOP[..instruction_size]);
            if self.emu.get_data().tracing {
                let trace_point = TracePoint {
                    address: address + nop_size,
                    asm_instruction: T1_NOP[..instruction_size].to_vec(),
                    registers,
                };
                self.emu.get_data_mut().trace_data.push(trace_point);
            }
            nop_size += instruction_size as u64;
        }
        // Set to same size as data_changed
        let mut original_instructions = manipulated_instructions.clone();
        // Read original data
        self.emu
            .mem_read(address, &mut original_instructions)
            .unwrap();
        self.program_counter += nop_size;
        FaultData {
            original_instructions,
            record: TracePoint {
                address,
                asm_instruction: manipulated_instructions,
                registers,
            },
            fault: *fault,
        }
    }

    fn emulate_fault(&mut self, fault: &SimulationFaultRecord) -> FaultData {
        match fault.fault_type {
            FaultType::Glitch(number_of_nops) => self.emulate_glitch(number_of_nops, fault),
        }
    }
}
