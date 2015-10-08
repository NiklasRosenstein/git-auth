@echo off
SET _dirname=%~dp0
SET PYTHONPATH=%_dirname%..;%PYTHONPATH%
python3 "%_dirname%git-auth.py" %*
