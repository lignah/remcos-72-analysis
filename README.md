# Remcos 7.2.0 Pro Analysis
Windows Remcos RAT 샘플에 대한 정적, 동적 분석

샘플 바이너리는 이 저장소에 없음

- 보고서: [report.md](report.md)
- YARA: [remcos.yar](remcos.yar)
- 스크린샷: [screenshots/](screenshots/)

## Sample
- SHA256: `73b8f80db93983c804bb8d8b2eb7beb1c11b2adb3564697ac3c5f340f502d578`
- Family: Remcos 7.2.0 Pro
- Arch: PE64 MSVC (unpacked)

## Lab
- Guest: Windows 10 Pro x64, FLARE-VM
- Hypervisor: VMware, Host-only
- Net: FakeNet-NG (no live C2)

## Findings (short)
- Config in `RCDATA/SETTINGS`, RC4, keylen=0xD9
- C2: `actualizadoswin11.kozow.com:6000`
- Persist: `%ProgramData%\windows11\windows11.exe` + HKCU Run
- Campaign: FEBRERO 2026 / ID `Windows11-75EBNI`