fn main() {
    let processes = memhack::get_processes("notepad.exe");
    let notepad_process = *processes.get(0).unwrap();

    let process = memhack::open_process(notepad_process);

    let process_unwrap = process.unwrap();

    // The address to write to
    let address = 0xe8e0060;

    // Write a byte to memory
    let mut vec: Vec<u8> = Vec::new();
    vec.push(0xDA);

    memhack::write_process_memory(process_unwrap, address, vec).unwrap();

    // Read a byte from memory
    let program_bytes = memhack::read_process_memory(process_unwrap, address, 10);
    println!("Byte: {}", program_bytes.unwrap().get(0).unwrap());
}
