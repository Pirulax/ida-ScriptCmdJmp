import ida_enum
import ida_hexrays
import idaapi
import idautils
import idc
import ida_kernwin
from typing import Optional

class EnumFinderPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Enum Finder Plugin for eScriptCommands"
    help = "Jump to eScriptCommands enum usage in handler functions"
    wanted_name = "ScriptCmdJmp"
    wanted_hotkey = "H"  # H as in (H)andler

    def init(self) -> int:
        """Initialize the plugin"""
        print("Loading EnumFinderPlugin was OK")
        return idaapi.PLUGIN_OK
    
    def run(self, arg: int) -> None:
        """Run the plugin when the hotkey is pressed"""
        self.show_enum_finder_dialog()
        
    def term(self) -> None:
        """Terminate the plugin"""
        pass

    def get_all_commands(self):
        """Get all available script command names (`COMMAND_*`)"""

        commands: dict[str, int] = {}

        enum = ida_enum.get_enum('eScriptCommands')
        class Visitor(ida_enum.enum_member_visitor_t):
            def visit_enum_member(self, cid, value):
                commands[str(ida_enum.get_enum_member_name(cid))] = value
                return 0
        ida_enum.for_all_enum_members(enum, Visitor())

        return commands

    def get_command_id(self, enum_name: str) -> Optional[int]:
        """Get an enum value from the cache or search for it"""
        
        return ida_enum.get_enum_member_value(
            ida_enum.get_enum_member_by_name(enum_name if enum_name.startswith('COMMAND_') else f'COMMAND_{enum_name}')
        )

    def get_handler_function(self, func_name: str) -> Optional[int]:
        """Find a function by name and return its address"""
        for fn in idautils.Functions():
            if idc.demangle_name(idc.get_func_name(fn), idc.get_inf_attr(idc.INF_SHORT_DN)) == func_name:
                return fn

        return None

    def get_handler_function_name(self, command_name: int) -> Optional[str]:
        """Find the appropriate handler function based on enum value programmatically"""
        # Calculate the function name based on the enum value range
        # Assuming a pattern like ProcessCommandsXXXToYYY where XXX is the floor of hundreds
        from_id = (command_name // 100) * 100
        return f"CRunningScript::ProcessCommands{from_id}To{from_id + 99}(int)"

    def find_command_in_handler(self, handler_fn: int, command_id: int) -> Optional[int]:
        """Find a text string within a function's disassembly"""
        func = idaapi.get_func(handler_fn)
        if not func:
            return None
        
        # Decompile the function
        cfunc = ida_hexrays.decompile(func, flags=ida_hexrays.DECOMP_ALL_BLKS)
        if not cfunc:
            ida_kernwin.warning(f"Failed to decompile handler function at 0x{handler_fn:X}")
            return None

        # Generate pseudocode for this function (Populates `cfunc.treeitems`)
        str(cfunc)

        for citem in cfunc.treeitems:
            # Find the main switch
            if citem.cinsn.op != idaapi.cit_switch:
                continue

            # Iterate switch cases
            for c in citem.cinsn.cswitch.cases:
                # Check if case contains the command ID
                if command_id not in c.values:
                    continue
                # For whatever reason this case may not have an address, return main switch's instead
                if c.ea == idaapi.BADADDR:
                    ida_kernwin.warning("Couldn't find command case address, jumping to main switch's instead")
                    return citem.ea

                # Return the case's ea
                return c.ea

        return None

    def navigate_to_handler(self, command_name: str) -> bool:
        """Find an enum and navigate to its usage"""

        print(f"[+] Looking for eScriptCommands::{command_name}")
        
        # Get the enum value
        command_id = self.get_command_id(command_name)
        if command_id is None:
            ida_kernwin.warning(f"Could not find enum named 'eScriptCommands::{command_name}'")
            return False
        
        print(f"[+] Found enum value: {command_id}")
        
        # Find the function that handles this enum
        func_name = self.get_handler_function_name(command_id)
        if not func_name:
            ida_kernwin.warning(f"No handler function found for enum value {command_id}")
            return False
        
        print(f"[+] Looking for function: {func_name}")
        func_addr = self.get_handler_function(func_name)
        if func_addr is None:
            ida_kernwin.warning(f"Could not find function '{func_name}'")
            return False
        
        print(f"[+] Found function at address: 0x{func_addr:X}")
        
        # Search for the enum name in the function
        found_addr = self.find_command_in_handler(func_addr, command_id)
        if found_addr is None:
            ida_kernwin.warning(f"Could not find '{command_name}' in function {func_name}")
            return False
        
        # Jump to the location
        print(f"[+] Found handler case at address: 0x{found_addr:X}")
        idaapi.jumpto(found_addr)
        return True

    def show_enum_finder_dialog(self) -> None:
        """Display the enum finder dialog"""

        # Create and show the form
        command_names = list(self.get_all_commands().keys())
        class EnumChooserDialog(ida_kernwin.Form):
            """Custom form with searchable dropdown for enum selection"""
            
            def __init__(self):
                # Define the form
                ida_kernwin.Form.__init__(
                    self,
                    r"""STARTITEM 0
                        Jump to script command handler

                        <##Select enum value:{D}:0:40>
                    """,
                    {
                        'D': ida_kernwin.Form.DropdownListControl(
                            items=command_names,
                            readonly=False,  # Allow typing for search
                            selval=command_names[0]
                        )
                    }
                )
            
            def OnFormChange(self, fid: int) -> int:
                """Handle form changes (enables search functionality)"""
                return 1

        dialog, _ = EnumChooserDialog().Compile()
        ok = dialog.Execute()
        
        if ok:
            self.navigate_to_handler(dialog['D'].value)
        
        dialog.Free()

# Register the plugin
def PLUGIN_ENTRY() -> EnumFinderPlugin:
    return EnumFinderPlugin()
