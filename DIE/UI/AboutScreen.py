__author__ = 'yanivb'

from idaapi import Form
import os
import DIE.Lib.DieConfig

class About(Form):

    def __init__(self):

        Form.__init__(self,
                      (r"BUTTON YES* NONE\n"
                       r"BUTTON NO NONE\n"
                       r"BUTTON CANCEL NONE\n"
                       r"DIE - Dynamic IDA Enrichment\n"
                       r"{FormChangeCb}\n"
                       r"            {imgDIE}\n"
                       r"DIE - Dynamic IDA Enrichment Framework\n"
                       r"Version 0.1\n"
                       r"\n"
                       r"Written by: Yaniv Balmas.\n"
                      ), {
                'imgDIE'        : Form.StringLabel(""),
                'FormChangeCb'  : Form.FormChangeCb(self.OnFormChange),
            })
        self.Compile()

    def OnFormChange(self, fid):

        config = DIE.Lib.DieConfig.get_config()
        # Form initialization
        if fid == -1:

            self.SetControlValue(self.imgDIE, "<img src='%s'>" % os.path.join(config.icons_path, "logo.png"))

        # Form OK pressed
        if fid == -2:
            pass

        return 1


