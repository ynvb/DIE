__author__ = 'yanivb'

from idaapi import Form
import os
import DIE.Lib.DieConfig

class About(Form):

    def __init__(self):

        Form.__init__(self,
r"""BUTTON YES* NONE
BUTTON NO NONE
BUTTON CANCEL NONE
DIE - Dynamic IDA Enrichment
{FormChangeCb}
            {imgDIE}
DIE - Dynamic IDA Enrichment Framework
Version 0.1

Written by: Yaniv Balmas.
""", {
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


