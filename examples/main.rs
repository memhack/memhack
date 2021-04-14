fn main() {
    let processes = memhack::get_processes("notepad.exe");
    let notepad_process = *processes.get(0).unwrap();

    let process = memhack::open_process(notepad_process);

    let process_unwrap = process.unwrap();

    let program_bytes = memhack::read_process_memory(process_unwrap, 0x0, 10);

    println!("Byte: {}", program_bytes.unwrap().get(0).unwrap());
}
