D.I.E
=====
Dynamic IDA Enrichment Framework

DIE is an IDA python plugin designed to enrich the default IDA static analysis with dynamic data.
This is done using the IDA Debugger API, by placing breakpoints in key locations and saving the current system context once those breakpoints are hit.

The saved context consist of function arguments and register states, and it is saved on every function CALL and RETURN.

DIE takes advantage of the IDA`s powerfull analysis engine and when context is taken, DIE is fully aware of known function prototypes, data types, structures, union, arrays and basically every piece of data IDA provides during static analysis.

Once context has been saved, DIE attempts to parse the individual data types based on an extendable parser framework.
If function prototype is avilable (in case of library function, or previously analyzed function),  DIE will try to use the apropriate parser.
If function prototype is not known, DIE will attempt to guess the value.

The resault is a dynamic databse that holds parsed runtime arguments, which are avilable to the user during static analysis.

Installation
------------

1. Install Prerequists:
    a. Python 2.7
    b. Pyside  - install using 'pip insatll pyside' or your favorite package manager
    c. yapsy   - install using 'pip install yapsy' or your favorite package manager
    d. pywin   - install via http://sourceforge.net/projects/pywin32/files/pywin32/

2. 
3. Copy `die.py` and `DIE` directory into your IDA plugin directory 


