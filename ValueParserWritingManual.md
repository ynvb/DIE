Value Parser Plugin Writing Manual
==================================

DIE's dynamic analysis abilities are only as good as its value parsers.
Value parser plugins are the beating heart of DIE as they parse the collected runtime values and transform them from
raw hex values into something we can actually understand and use.

Value parser plugin main logic is fairly simple, they receive two input arguments:
* The raw value collected at runtime as a hex value.
* [Optional] Type information as an `idaapi.type_info_t` object

They then try to parse the raw value to a "Human Readable" form and register it as a `ParsedValue` object if successful.

If no type information is provided, a parser may still choose to guess the parsed value and assign a relevant guessing
 score in scale of 1-10. The better the guess, the higher the score. (A score of 0 is considered a perfect match and is
 reserved to cases where the type is known).

If a value is guessed, more then one `ParsedValue` may be assigned to it, since there may be more then one guess for the
 correct value.

In order to ease the development of parser plugins, a `PluginManager` object has been added to DIE.
 This `PluginManager` takes care of most of internal integration with DIE, so that if you want to add a new parser
 plugin all that is left to do is to implement the parsing logic.


Value Parser Plugin Example
---------------------------

A Boolean parser makes a perfect example of creating your own value parser plugin.
We would like our to receive either the raw value `0x0` or `0x1 `and register the ParsedValue `True` of `False` accordingly.

 {ADD ILLUSTRATION}

### Before you begin

Each parser plugin is composed of two files, both of which must be located at the same directory.
 1. The main python file holding the parsing logic.
 2. A `.yapsy-plugin` file holding the plugin information.

### Step 1: Creating a plugin information file

The `yapsy-plugin` file should contain at least the following information, for the `PluginManager` to recognize the
plugin and for the plugin's author eternal fame.

```ini
[Core]
Name = BoolParser
Module = BoolParser

[Documentation]
Author = Anonymous Author
Description = Just a simple boolean parser
```

**Note:** the `Module` value must match the parser class name.

### Step 2: Create a new plugin parser class

Simply create a new class which inherits from `DataPluginBase`.

```python
class BoolParser(DataPluginBase):
```

### Step 3: Register type

After initializing the class and it's parent class, the plugin type should be set.
`self.setPluginType` marks the name that will be given to each of the parsed values registered by this plugin.
Only a single value may be registered as a plugin type.
In our case, we simply register the type `"Bool"`.

```python
    def __init__(self):
        super(BoolParser, self).__init__()
    
        self.setPluginType("Bool")
```

### Step 4: Register Supported Types [Optional]

As stated before, DIE's `PluginManager` receives both the raw value and the type info for any collected runtime value,
It then has to decide which of the parser plugins should be assigned to parser this value.
If type info is not available, there is no way of telling which of the parser plugins should be assign,
so the `PluginManager` simply assigns all of the plugin parsers, and request they will attempt to guess the value.
On the other hand, if the type information is known, The `PluginManager` should receive some information from each
plugin that will inform him of the types supported by this plugin.

This is exactly what the `registerSupportedTypes` method is designed to do. it will be called upon plugin initialization
and will inform the plugin manager of the supported types trough the `addSupportedType` routine.
Each supported type is simply the name of the type supported by this plugin (e.g `"INT"`, `"CHAR"`, `"BOOL"`).

Adding a supported type is optional, and multiple types can be registered to the same plugin.
(The second argument passed to `addSupportedValue` is a description value and is not currently implemented).

In our case, we notify the `PluginManager` that the type `"BOOL"` should be parsed by this parser.

```python
    def registerSupportedTypes(self):
        """
        Register string types
        @return:
        """
        self.addSuportedType("BOOL", 0)
```

### Step 5: Provide any additional matching logic [Optional]

In case type name matching (which is done by the `registerSupportedTypes` method) is not enough in order to validate that this plugin can parse the passed raw value, additional matching logic can be added by implementing the `matchType` method and checking the passed `idaapi.type_info_t` object.

In our case there is no more logic, so we just return `True`.

```python
    def matchType(self, type):
        """
        @param type: IDA type_info_t object
        """
    
        # Add any additional logic here
        return True
```

### Step 6: Implement parsing\guessing logic.

All that is left to do now is to implement the actual parsing\guessing logic.
Parsing logic is done when the type is known and the `ParserManager` have successfully matched the type against this plugin. Guessing logic on the other hand is done when no type have been provided.

The reason for breaking this logic into two different methods is that there may be cases where the logic changes between parsing a value and guessing it. This is not the case of our BoolParser though.

Whenever a value is parsed successfully its parsed value should be registered using the `self.addParsedvalue`.

`self.addParsedValue` has 4 arguments:
1. The parsed value
2. The parsing score
3. A description of the parsed value
4. The raw value representation.

In the case of our simple Boolean parser, the parsing and guessing methods should look like this:

```python
    def guessValues(self, rawValue):
        """
        Guess string values
        """
        if rawValue == 1:   # Guess True
            self.addParsedvalue(value="True", score=5, description="Boolean", raw=hex(rawValue))
            return True
    
        if rawValue == 0:   # Guess False
            self.addParsedvalue(value="False", score=5, description="Boolean", raw=hex(rawValue))
            return True
    
        return False
    
    def parseValue(self, rawValue):
        """
        Parse the string value
        @return:
        """
        if rawValue == 1:   # Parse True
            self.addParsedvalue(value="True", score=0, description="Boolean", raw=hex(rawValue))
            return True
    
        if rawValue == 0:   # Parse False
            self.addParsedvalue(value="False", score=0, description="Boolean", raw=hex(rawValue))
            return True
    
        return False
```

If you are still unsure of how to create your own plugin, feel free to check out the existing parser plugins code.
