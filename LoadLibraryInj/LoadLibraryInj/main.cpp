#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <filesystem>
#include <fstream>

DWORD GetProcIdByName(const char* name)
{
    if (!name || !strstr(name, ".exe"))
        return 0;

    DWORD returnedPid = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot)
    {
        PROCESSENTRY32 pe32{};
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32))
        {
            do
            {
                if (!strcmp(pe32.szExeFile, name))
                {
                    returnedPid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
    }

    return returnedPid;
}

bool Is64BitProcess(HANDLE hProcess)
{
    if (!hProcess)
        return false;

    BOOL result = FALSE;
    IsWow64Process(hProcess, &result);

    // NOTE: When we set our program to x86, this is true, but when we see it to x64, it's false. Hance the '!'.
    return !result;
}

int main()
{
    SetConsoleTitleA("LoadLibraryInj");

    // Read process name input.
    std::string selectedProcess = "";
    std::cout << "Process name: ";
    std::cin >> selectedProcess;

    char szFile[100];
    OPENFILENAME ofn{};
    ZeroMemory(&ofn, sizeof(ofn));

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFile = szFile;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "All Files\0*.*\0DLL Files\0*.dll\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = 0;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = 0;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    // Open a file dialog.
    GetOpenFileName(&ofn);

    // Ensure we always have the ".exe" extension.
    if (!strstr(selectedProcess.c_str(), ".exe"))
        selectedProcess += ".exe";

    // Define a file to select and check if it's valid.
    std::string selectedFile = szFile;
    if (selectedFile.empty() || !std::filesystem::exists(selectedFile))
    {
        printf("Invalid file. Ensure that %s exists.\n", selectedFile.c_str());
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        return 0;
    }
    std::ifstream file(selectedFile.c_str(), std::ios::binary | std::ios::ate);
    if (file.fail())
    {
        printf("Failed to open %s.\n", selectedFile.c_str());
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        return 0;
    }

    auto fileSize = file.tellg();
    if (fileSize < 0x1000)
    {
        printf("Invalid file size.\n");
        file.close();
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        return 0;
    }

    // Create new byte array the size of the file size.
    BYTE* data = new BYTE[fileSize];
    if (!data)
    {
        printf("Invalid source data (0x%p)\n", data);
        file.close();
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        return 0;
    }

    // Seek to beginning of file.
    file.seekg(0x0, std::ios::beg);
    file.read(reinterpret_cast<char*>(data), fileSize);
    file.close();

    // Ensure we have a valid DOS signature.
    if (reinterpret_cast<PIMAGE_DOS_HEADER>(data)->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("Invalid DOS signature.");
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        delete[] data;
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(data + reinterpret_cast<PIMAGE_DOS_HEADER>(data)->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("Invalid NT signature.");
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        delete[] data;
        return 0;
    }

    // No longer need buffer.
    delete[] data;

    // Get the process id of a process by it's name and check if it's valid.
    DWORD processId = GetProcIdByName(selectedProcess.c_str());
    if (processId <= 0x4)
    {
        printf("Invalid process id %i (0x%x). Ensure the process is running.\n", processId, processId);
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        return 0;
    }

    // Open a handle to the that process and check if it's valid.
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processId);
    if (!hProcess)
    {
        printf("Failed to open a handle to process id %i.\n", processId);
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        return 0;
    }

    // X86: IMAGE_FILE_MACHINE_I386
    // x64: IMAGE_FILE_MACHINE_AMD64
    if (Is64BitProcess(hProcess) && ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        printf("Failed: Process is 64-bit, but module is 32-bit.\n");
        CloseHandle(hProcess);
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        return 0;
    }
    else if (!Is64BitProcess(hProcess) && ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        printf("Failed: Process is 32-bit, but module is 64-bit.\n");
        CloseHandle(hProcess);
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        return 0;
    }

    // Allocate memory for your module in the memory.
    LPVOID address = VirtualAllocEx(hProcess, nullptr, selectedFile.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!address)
    {
        printf("Failed to allocate memory for address (0x%p).\n", address);
        CloseHandle(hProcess);
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        return 0;
    }

    // Write the DLL name with the size to the process memory.
    if (!WriteProcessMemory(hProcess, address, selectedFile.c_str(), selectedFile.size(), nullptr))
    {
        printf("Failed to call WriteProcessMemory on process id %i\n.", processId);
        CloseHandle(hProcess);
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        return 0;
    }

    // Create a remote thread for your module.
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), address, 0, 0);
    if (!hThread)
    {
        printf("Failed to create a remote thread in process id %i\n.", processId);
        CloseHandle(hProcess);
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        return 0;
    }

    // Check if the thread state is valid.
    if (WaitForSingleObject(hThread, INFINITE) != WAIT_OBJECT_0 /*The state of the specified object is signaled*/)
    {
        printf("Failed to wait for load library ThreadObject.\n");
        VirtualFreeEx(hProcess, address, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        return 0;
    }

    // Cleanup.
    CloseHandle(hProcess);
    CloseHandle(hThread);

    std::string toTrim = selectedFile;
    size_t lastSlash = toTrim.find_last_of("\\") + 1;
    std::string finalString = toTrim.substr(lastSlash);

    printf("Successfully loaded %s into process id %i!\n", finalString.c_str(), processId);
    printf("Closing in five seconds.\n");

    // Bye bye!
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    return EXIT_SUCCESS;
}
