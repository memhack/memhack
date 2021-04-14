fn main() {
    windows::build!(
        Windows::Win32::WindowsAndMessaging::MessageBoxA,
        Windows::Win32::Debug::ReadProcessMemory,
        Windows::Win32::SystemServices::OpenProcess,
        Windows::Win32::Debug::GetLastError,
        Windows::Win32::Debug::WriteProcessMemory
    );
}
