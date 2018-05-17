class DIE_go_Handler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        go_here()
        return True

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def go_here():
    print "Hello!!"

def add_menu_items():
    DIE_go_description = idaapi.action_desc_t(
        'TEST:test',
        'Go from current location',
        DIE_go_Handler(),
        'Alt+n',
        'Tooltop description',
        -1)
        
    idaapi.register_action(DIE_go_description)
    idaapi.attach_action_to_menu(
        'Edit/Test/Go',
        'TEST:test',
        idaapi.SETMENU_APP)


print "Adding menu items..."
try:
    add_menu_items()
except Exception as ex:
    print "Error: Excepton {}".format(ex)
