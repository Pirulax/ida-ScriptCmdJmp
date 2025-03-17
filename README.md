# What's this?
Script to help you easily jump to the handler of a given script command.
The script command is identified by it's name (From `eScriptCommands`, with or without the `COMMAND_` prefix).

# Installation
Copy the script to  `<IDA Installation Folder>/plugins/` folder

# Usage
Default hotkey is `H` (as in `H`andler), can be changed in `Options->Shortcuts` (Action name is `ScriptCmdJmp`)

# Notes
The script is really in beta, so bugs may occur. Though, at worst (in theory) it won't find the exact case address.
It uses the `eScriptCommands` enum, so if something doesn't work, make sure it's correct.

# License
MIT
