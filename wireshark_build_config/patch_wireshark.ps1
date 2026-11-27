<#
.SYNOPSIS
    Applies source-level workarounds to a checked-out Wireshark tree before building.

.DESCRIPTION
    Intended for Windows CI builds using a minimal CMake preset (e.g., ENABLE_PCAP=OFF).
    Stored under wireshark_build_config/ so edits automatically invalidate the CI cache key.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Branch,

    [string]$WiresharkDir = "wireshark"
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

switch ($Branch) {
    "release-4.0" {
        # Workaround for Wireshark release-4.0 (Windows only):
        #
        # Affected file: capture/capture-wpcap.c (the Windows-only WinPcap/Npcap wrapper;
        # Linux and macOS builds do not compile this file).
        #
        # Cause: When building with ENABLE_PCAP=OFF, HAVE_LIBPCAP is undefined and compilation
        # falls into the #else branch, which defines gather_caplibs_compile_info(feature_list l)
        # without including "wsutil/feature_list.h". MSVC fails with error C2146 because
        # feature_list is an unknown type.
        #
        # Versions: Only needed on release-4.0; fixed upstream in release-4.2 and later.
        $file = Join-Path $WiresharkDir "capture/capture-wpcap.c"
        $content = Get-Content -Path $file -Raw

        if ($content -match 'wsutil/feature_list\.h') {
            Write-Host "Already patched: $file"
            break
        }

        $regex = [regex]'(?m)^([ \t]*#[ \t]*include[ \t]+[<"]config\.h[>"])(\r?\n)'
        $updated = $regex.Replace($content, '$1$2#include "wsutil/feature_list.h"$2', 1)

        if ($updated -eq $content) {
            throw "Failed to patch ${file}: could not find config.h include."
        }

        Set-Content -Path $file -Value $updated -NoNewline
        git -C $WiresharkDir diff capture/capture-wpcap.c
    }
    default {
        Write-Host "No source patches configured for $Branch."
    }
}
