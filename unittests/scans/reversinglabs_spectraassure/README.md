# Test files

files that wil be used by the `unittests/tools/test_reversinglabs_spectraassure_parser.py`

- FD13-FullUSB.zip-report.rl.json
- putty_win_x64-0.80.exe-report.rl.json
- HxDSetup_2.5.0.exe-report.rl.json

## Peculiarities per file

- FD13-FullUSB.zip-report.rl.json	1 secret , no CVE
- putty_win_x64-0.80.exe-report.rl.json	One CVE Finding
- HxDSetup_2.5.0.exe-report.rl.json	Multiple (12) Findings but components with the same name but different sha256
