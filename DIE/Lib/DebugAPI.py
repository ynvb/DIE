

#########################
#### General Imports ####
#########################
import sys
import os
import cProfile
import pstats
import StringIO
import time

from idaapi import *
from idautils import *
from idc import *

### DIE Imports###
import DIE.Lib.DieConfig
import DIE.Lib.DataParser
from DIE.Lib.DIE_Exceptions import FuncCallExceedMax, DieCallStackPopError, DieThunkFunctionDetected
from DIE.Lib.CallStack import *
from DIE.Lib.DbgImports import *
from DIE.Lib.IDAConnector import get_cur_ea, is_call, is_ida_debugger_present
import DIE.Lib.DIEDb

##########################
####     Defines      ####
##########################
WAS_USER_BREAKPOINT = 0x1

class DebugHooker(DBG_Hooks):
    """
    IDA Debug hooking functionality
    """
    def __init__(self, is_dbg_pause=False, is_dbg_profile=False, is_dyn_bp=False):

        try:
            self.logger = logging.getLogger(__name__)
            self.config = DIE.Lib.DieConfig.get_config()
            data_parser = DIE.Lib.DataParser.getParser()

            plugin_path = self.config.parser_path

            data_parser.set_plugin_path(plugin_path)
            data_parser.loadPlugins()

            # Breakpoint Exceptions
            self.bp_handler = DIE.Lib.BpHandler.get_bp_handler()
            self.bp_handler.load_exceptions(DIE.Lib.DIEDb.get_db())

            ### Debugging ###
            DBG_Hooks.__init__(self)                        # IDA Debug Hooking API
            self.isHooked = False                           # Is debugger currently hooked

            self.runtime_imports = DbgImports()             # Runtime import addresses

            self.callStack = {}                             # Function call-stack dictionary
                                                            # (Key: ThreadId, Value: Thread specific Call-Stack)
            self.current_callstack = None                   # A pointer to the currently active call-stack

            self.prev_bp_ea = None                          # Address of previously hit breakpoint
            self.end_bp = None                              # If set framework will stop once this bp was reached

            self.start_time = None                          # Debugging start time
            self.end_time = None                            # Debugging end time

            ### Flags
            self.is_dbg_pause = is_dbg_pause                # Pause execution at each breakpoint
            self.is_dbg_profile = is_dbg_profile            # Profiling flag
            self.is_dyn_breakpoints = is_dyn_bp             # Should breakpoint be set dynamically or statically
            self.update_imports = True                      # IAT updating flag (when set runtime_imports will be updated)

            ### Debugging
            self.pr = None                                  # Profiling object (for debug only)

        except Exception as ex:
            self.logger.exception("Failed to initialize DebugAPI: %s", ex)
            return

    def Hook(self):
        """
        Hook to IDA Debugger
        """

        if self.isHooked:   # Release any current hooks
            self.logger.debug("Debugger is already hooked, releasing previous hook.")
            self.UnHook()

        try:
            if not is_ida_debugger_present():
                self.logger.error("DIE cannot be started with no debugger defined.")
                return

            self.logger.info("Hooking to debugger.")
            self.hook()
            self.isHooked = True

        except Exception as ex:
            self.logger.exception("Failed to hook debugger", ex)
            sys.exit(1)

    def UnHook(self):
        """
        Release hooks from IDA Debugger
        """
        try:
            self.logger.info("Removing previous debugger hooks.")
            self.unhook()
            self.isHooked = False

        except Exception as ex:
            self.logger.exception("Failed to hook debugger", ex)
            raise RuntimeError("Failed to unhook debugger")

    def update_iat(self):
        """
        Update the current IAT state and reset flag
        """
        self.runtime_imports.getImportTableData()
        self.update_imports = False

######################################################################
# Debugger Hooking Callback Routines

    def dbg_bpt(self, tid, ea):
        """
        'Hit Debug Breakpoint' Callback -
         this callback gets called once a breakpoint has been reached -
         this means we can either be in a CALL or a RET instruction.
        """
        try:
            # If final breakpoint has been reached. skip all further breakpoints.
            if self.end_bp is not None and ea == self.end_bp:
                self.logger.info("Final breakpoint reached at %s. context logging is stopped.", hex(ea))
                self.bp_handler.unsetBPs()
                request_continue_process()
                run_requests()
                return 0

            # If required, update IAT
            if self.update_imports:
                self.update_iat()

            # Set current call-stack
            if tid not in self.callStack:
                idaapi.msg("Creating new callstack for thread %d\n" % tid)
                self.callStack[tid] = CallStack()

            self.current_callstack = self.callStack[tid]

            # Did we just return from a function call?
            if self.bp_handler.isRetBP(ea):
                try:
                    self.current_callstack.pop()
                except DieCallStackPopError:
                    self.logger.exception("Error while popping function from callstack")

                self.bp_handler.removeRetBP(ea)
                if not is_call(ea):
                    request_continue_process()
                    run_requests()

            # Is this a CALL instruction?
            if is_call(ea):
                self.prev_bp_ea = ea  # Set prev ea
                self.bp_handler.addRetBP(ea)
                if not self.is_dbg_pause:
                    request_step_into()  # Great, step into the called function
                    run_requests()  # Execute dbg_step_into callback.

            return 0

        except Exception as ex:
            self.logger.exception("Failed while handling breakpoint at %s:", ea, ex)
            return 1

    def dbg_step_into(self):
        """
        Step into gets called whenever we step into a CALL instruction.
        The callback checks if the function we have stepped into is a library function (in which case
        no BPs should be set inside it, so we need to skip to the next RET instruction), or we have
        stepped into a native function (in which case we just need to gather data and continue to next BP).
        """
        try:
            refresh_debugger_memory()
            ea = get_cur_ea()

            # If function in IAT, retrieve IAT details
            iatEA, library_name = self.runtime_imports.find_func_iat_adrs(ea)

            # If stepped into an excepted function, remove calling bp and skip over.
            if self.bp_handler.is_exception_func(ea, iatEA):
                self.logger.debug("Removing breakpoint from %s", hex(self.prev_bp_ea))
                self.bp_handler.removeBP(self.prev_bp_ea)
                return 0

             # Save CALL context
            func_call_num = self.current_callstack.push(ea, iatEA, library_name=library_name, calling_ea=self.prev_bp_ea)

            (func_adr, func_name) = self.current_callstack.get_top_func_data()
            if func_adr is not None and func_name is not None:
                self.logger.debug("Stepped into function %s at address %s", func_adr, func_name)

            # TODO: this should be redefined to a better condition + also need to check if module is excluded
            if not self.runtime_imports.is_func_imported(ea) and self.is_dyn_breakpoints:
                self.bp_handler.walk_function(ea)

            # Check if total number of function calls exceeded the max configured value
            if func_call_num > self.config.debugging.max_func_call:
                self.make_exception_last_func()

        except DieCallStackPushError as ex:
            self._callStackPushErrorHandler(ex.ea)

        except DieThunkFunctionDetected as ex:
            #TODO: Handle cases where a thunk function (jmp wrapper) has been encountered.
            pass

        except Exception as ex:
            self.logger.exception("failed while stepping into breakpoint: %s", ex)
            return 0

        finally:
            # Continue Debugging
            request_continue_process()
            run_requests()
            return 0

    def dbg_step_until_ret(self):
        """
        Step until return gets called when entering a library function.
        the debugger will stop at the next instruction after the RET.
        Context info needs to be collected here and execution should be resumed.
        """
        try:
            # Save Return Context
            self.current_callstack.pop()

        except DieCallStackPopError as ex:
            self.logger.exception("Error while popping function from callstack")
            #TODO: Handle this exception

        except Exception as ex:
            self.logger.exception("Failed while stepping until return: %s", ex)

        finally:
            if not self.is_dbg_pause:
                request_continue_process()
                run_requests()

    def dbg_thread_start(self, pid, tid, ea):
        """
        TODO: debugging, should be implemented fully.
        @return:
        """
        try:
            # If no call-stack exist for this thread, create one.
            if not tid in self.callStack:
                self.callStack[tid] = CallStack()

            if not self.is_dbg_pause:
                request_continue_process()
                run_requests()

        except Exception as ex:
            self.logger.exception("Failed while handling new thread: %s", ex)

    def dbg_process_exit(self, pid, tid, ea, exit_code):
        """
        TODO: debugging, should be implemented fully.
        @return:
        """
        try:
            if self.is_dbg_profile:
                self.profile_stop()

        except Exception as ex:
            self.logger.error("Failed to stop profiling: %s", ex)

        try:
            self.end_time = time.time()
            self.bp_handler.unsetBPs()

            die_db = DIE.Lib.DIEDb.get_db()

            die_db.add_run_info(self.callStack,
                                self.start_time,
                                self.end_time,
                                idaapi.get_input_file_path(),
                                idautils.GetInputFileMD5())

            self.bp_handler.save_exceptions(die_db)

        except Exception as ex:
            self.logger.exception("Failed while finalizing DIE run: %s", ex)

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        """
        TODO: debugging, should be implemented fully.
        @return:
        """
        return True

    def dbg_continue_process(self):
        return True

###############################################
# Convenience Function

    def make_exception_last_func(self):
        """
        Adds the last called function to exceptions
        @return: True if succeeded, otherwise False
        """
        try:
            (except_ea, except_name) = self.current_callstack.get_top_func_data()

            self.logger.debug("Function %s was called more then %d times.",
                              except_name, self.config.debugging.max_func_call)

            self.logger.debug("Removing breakpoint from %s", hex(self.prev_bp_ea))
            self.bp_handler.removeBP(self.prev_bp_ea)

            # Add function to exceptions, and reload breakpoints
            self.logger.debug("Adding address %s to exception list", except_ea)
            self.bp_handler.add_bp_ea_exception(except_ea)
            self.logger.debug("Adding function name %s to exception list", except_name)
            #self.bp_handler.add_bp_funcname_exception(except_name, reload_bps=True)
            self.bp_handler.add_bp_funcname_exception(except_name)

            return True

        except Exception as ex:
            self.logger.exception("Error while creating exception: %s", ex)
            return False

    def _callStackPushErrorHandler(self, ea, function_name=None):
        """
        Handle a failed attempt to push function to callstack
        @param ea: Function Address
        @param function_name: Function Name
        @return:
        """
        try:
            self.logger.info("Trying to walk un-pushed function %s for breakpoints", hex(ea))
            if not self.runtime_imports.is_func_imported(ea) and self.is_dyn_breakpoints:
                self.bp_handler.walk_function(ea)

        except Exception as ex:
            self.logger.exception("Failed to handle callstack push error for function: %s", hex(ea))

###############################################
#   Debugging

    def start_debug(self, start_func_ea=None, end_func_ea=None, auto_start=False):
        """
        Start Debugging
        @param start_func_ea: ea of function to start debugging from
        @param end_func_ea: ea of function to stop debugging end
        @param auto_start: Automatically start the debugger
        @rtype : object
        """
        try:
            if self.is_dbg_profile:
                self.profile_start()
        except Exception as ex:
            self.logger.error("Failed to start profiling: %s", ex)

        try:

            self.Hook()

            if start_func_ea is not None:
                self.is_dyn_breakpoints = True

                # If end function address was not explicitly defined, set to end of current function
                if end_func_ea is None:
                    self.end_bp = DIE.Lib.IDAConnector.get_function_end_address(start_func_ea)
                    self.bp_handler.addBP(self.end_bp, "FINAL_BP")

                # Walk current function
                self.bp_handler.walk_function(start_func_ea)

            else:
                self.bp_handler.setBPs()

            # Set start time
            if self.start_time is None:
                self.start_time = time.time()

            # start the process automatically
            if auto_start:
                request_start_process(None, None, None)
                run_requests()

        except Exception as ex:
            self.logger.exception("Error while staring debugger: %s", ex)

################################################################################
# Profiling, for debug usage only.

    def profile_start(self):
        """
        Start profiling the application.
        @return:
        """

        # Start Profiling
        self.pr = cProfile.Profile()
        self.pr.enable()

    def profile_stop(self):
        """
        Stop profiling the application and display results.
        @return:
        """
        # If profiling is activated:
        if self.pr is None:
            return False

        self.pr.disable()
        s = StringIO.StringIO()
        sortby = 'tottime'
        ps = pstats.Stats(self.pr, stream=s).sort_stats(sortby)
        ps.print_stats()

        idaapi.msg("%s\n" % (s.getvalue(), ))