import random
import string
import cherrypy
from regdefs import *

class ReadRegister32(Register32):
    pass

class RegmapWebform:
    def __init__(self, regmap, split=8, posthook=None):
        self.regmap = regmap
        self.split = split
        self.posthook = posthook

    def render_field(self, reg, name, val, ro=False):
        rotext = "disabled=\"disabled\"" if ro else ""
        info = getattr(reg.__class__, name)
        if isinstance(info, int):
            chktext = "checked" if val else "unchecked"
            return """
                <input type="hidden" name="{}" value="0" />
                <input type="checkbox" id="{}" name="{}" value="1" {} {} />
                <label for="{}">{}</label><br>
            """.format(name, name, name, chktext, rotext, name, name)
        elif len(info) == 3:
            return """
                <label for="{}">{}:</label>
                <select name="{}" id="{}">
            """.format(name, name, name, name) + "".join("<option value=\"{}\" {}>{}</option>".format(int(v), 'selected' if int(v)==val else '', v.name) for v in info[2]) + """
                </select><br>
            """
        else:
            return """
                {}: 0x<input type="text" value="{x}" name="{}" {} /><br>
            """.format(name, val, name, rotext)

    def render_reg(self, name, acc):
        reg = acc.reg
        ro = isinstance(reg, ReadRegister32)
        rotext = "disabled=\"disabled\"" if ro else ""

        s = """
        <form method="post" action=""><fieldset>
            <legend>{}</legend>
        """.format(name)
        if acc.cls.__doc__:
            s += "<small><p>{}</p></small>".format(acc.cls.__doc__ or '')
        s += """
            <input type="hidden" name="_regname" value="{}" />
        """.format(name)

        if not reg._fields_list:
            s += """
                0x<input type="text" value="{:x}" name="_value" {} /><br>
            """.format(int(reg), rotext)
        else:
            s += "".join([self.render_field(reg, name, val, ro) for name, val in acc.reg.fields.items()])

        if not ro:
            s += """
                <input type="submit" value="Set" style="float: right;">
            """

        s += """
        </fieldset></form>
        """
        return s

    def _set_value(self, regname, vals):
        if "_value" in vals:
            getattr(self.regmap, regname).val = vals["_value"]
        else:
            getattr(self.regmap, regname).set(**vals)
        if self.posthook:
            self.posthook()

    @cherrypy.expose
    def index(self, **kwargs):
        cherrypy.response.headers["Cache-Control"] = "no-store"

        if cherrypy.request.method == "POST":
            regname = kwargs["_regname"]
            del kwargs["_regname"]
            self._set_value(regname, {k: isinstance(v, list) or int(v, 16) for k, v in kwargs.items()})

        s = """<html>
          <head><title>RSMS Detection Configurator</title><style>
            .row {
              display: flex;
            }
            .column {
              flex: 50%;
            }
          </style></head>
          <body>
          <div class="row"><div class="column">
        """
        regs_rendered = [self.render_reg(name, acc) for name, acc in self.regmap._accessor.items()]
        s += "".join(regs_rendered[:self.split])
        s += "</div><div class=\"column\">"
        if len(regs_rendered) > self.split:
            s += "".join(regs_rendered[self.split:])
        s += """
          </div></div>
          </body>
        </html>
        """

        return s

    @cherrypy.expose
    def generate(self, length=8):
        some_string = ''.join(random.sample(string.hexdigits, int(length)))
        cherrypy.session['mystring'] = some_string
        return some_string

    @cherrypy.expose
    def display(self):
        return cherrypy.session['mystring']

