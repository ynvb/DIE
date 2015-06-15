Dynamic IDA Enrichment (aka. DIE)
=================================

<p align="center">
<img src="https://github.com/ynvb/DIE/blob/master/DIE/icons/logo.png" alt="DIE Logo"/>
</p>

### What is it?

DIE is an IDA python plugin designed to enrich IDA`s static analysis with dynamic data.
This is done using the IDA Debugger API, by placing breakpoints in key locations and saving the current system context once those breakpoints are hit.

The saved context consist of function arguments and register states, and it is saved upon each function CALL and function RETURN.

DIE takes advantage of IDA`s powerful analysis engine so that when context is taken DIE is fully aware of known function prototypes, data types, structures, unions, arrays and basically every piece of information IDA provides during static analysis.

In order to take this one step further, once context has been saved, DIE attempts to parse the individual data types based on an integrated (and extensible!) value parser framework.

So for example, if the current context has a function argument with type 'CHAR *' DIE will dereference its address and show a human readable ASCII string as value.

If the current context holds a argument with unknown value, DIE will not give up and attempt to guess the value using all relevant parsers.

This parser framework is the real power behind DIE, parser plugins can parse anything from BOOL values to image files to injected code.

The resault is a dynamic databse that holds parsed runtime arguments, which are avilable to the user during static analysis.

### I'm not sure I got it, do you have an example?

Well, yes. I'm glad you asked!
These viedos shows DIE in action, check them out if you want to understand a little bit more about how it works.

#### Example Video I
[Bypass Password Protection](https://vimeo.com/130815897)
In which we are going to demonstrate how DIE can be used in order to bypass a (very) simple password protection scheme.

#### Example Video II
[Code Coverage](https://vimeo.com/130815898)
In which we will show you how running DIE before even looking at the static anlysis helps with code coverage, indirect calls, and function defenitions.

#### Example Video III
[Querying DieDB](https://vimeo.com/130815899)
In which we will show you how to use DIEDB to quickly locate the Explosive trojan de-obfuscation fuction.

### I want to write my own value parser plugin

Great, Value parser plugins are the heart of DIE. Without them DIE is practically usless.
Check out the [value parser writing manual](https://github.com/ynvb/DIE/blob/master/ValueParserWritingManual.md) and if your plugin turns out good, share it with the community!

Installation
------------
**Installation Prerequists:**

1. IDA > 6.6
2. Python 2.7
3. Yapsy     - install using `pip install yapsy` or your favorite package manager
4. Pywin32   - install via [PyWin32](http://sourceforge.net/projects/pywin32/files/pywin32/)
5. Sark      - install using `pip install -e git+https://github.com/tmr232/Sark.git#egg=Sark`
6. yaml      - install using `pip install pyyaml`
7. attrdict  - install using `pip install attrdict`

Both `sark` and `yapsy` can be installed using `pip install -r requirements.txt`.

**Install ida-python patch:**

1. If running under IDA 6.6:
   Extract the content of the `ida-python-patch.zip` file into your IDA directory.

2. If running under IDA 6.7:
   Replace the binaries found in `ida67_patch.zip` file with the original IDA binaries
   
3. If tunning under IDA 6.8:
    Everything works. Have fun.

Note that both of this patches are official patches compiled by hex-rays, and were created due to a bug in the relevant version.

**Install Plugin:**

1. Copy `DIE.py` and the `DIE` dir into your IDA plugin directory.
