echo on
echo %CD%
echo %PATH%
python --version
python -c "import struct; print(struct.calcsize('P') * 8)"
pip install -r dev-requirements.txt || goto :error

REM Use Chocolatey to install SWIG.
REM Only install swig if it isn't present (as a result of AppVeyor's caching).
REM SWIG 2.0.11 is the minimum required version, but it does not yet exist in
REM Chocolatey.
IF NOT EXIST C:\ProgramData\chocolatey\bin\swig.exe choco install swig --version 2.0.12 --allow-empty-checksums --yes --limit-output || goto :error
swig -version || goto :error

curl -Lo softhsm.zip https://github.com/disig/SoftHSM2-for-Windows/releases/download/v2.3.0/SoftHSM2-2.3.0-portable.zip || goto :error
7z -bb3 -oc:\\ x softhsm.zip || goto :error
softhsm2-util --init-token --slot 0 --label "A token" --pin 1234 --so-pin 123456 || goto :error


goto :EOF


:error
echo Failed with error #%errorlevel%.
exit /b %errorlevel%
