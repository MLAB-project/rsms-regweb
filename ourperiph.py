#!/usr/bin/env python3
from regdefs import *
from server import *

class HostMemAccessor:
    def __init__(self):
        self.devmem = open("/dev/mem", "w+b")

    def write(self, addr, data, width=8):
        base = align_down(addr)
        with mmap.mmap(self.devmem.fileno(), 16384, offset=base) as mm:
            mm.seek(addr - base, 0)
            mm.write(data.to_bytes(width // 8, byteorder='little'))

    def read(self, addr, width=8):
        base = align_down(addr)
        with mmap.mmap(self.devmem.fileno(), 16384, offset=base) as mm:
            mm.seek(addr - base, 0)
            return int.from_bytes(mm.read(width // 8), byteorder='little')

class DummyAccessor:
    def __init__(self):
        self.m = dict()

    def write(self, addr, val, **kwargs):
        self.m[addr] = val

    def read(self, addr, **kwargs):
        return self.m.get(addr, 0)

class E_CHANSEL(IntEnum):
    CH0 = 0
    CH1 = 1
    CH2 = 2
    CH3 = 3
    CH4 = 4
    CH5 = 5
    CH6 = 6
    CH7 = 7

class R_CTRL(Register32):
    RECORDING = 31
    BYPASS_FIR = 8
    RST    = 1
    EN     = 0

    DET0CH = 19, 17, E_CHANSEL
    DET0EN = 16
    DET1CH = 23, 21, E_CHANSEL
    DET1EN = 20

class R_SHAPEON(Register32, ContinuousRegister):
    '''DETECT pulse shape (ON duration)'''

class R_SHAPEOFF(Register32, ContinuousRegister):
    '''DETECT pulse shape (ON+OFF duration)'''

class R_DET0TH(Register32, ContinuousRegister):
    '''DET0: Theshold in signal level'''

class R_DET0DU(Register32, ContinuousRegister):
    '''DET0: Threshold in duration'''

class R_DET1TH(Register32, ContinuousRegister):
    '''DET1: Theshold in signal level'''

class R_DET1DU(Register32, ContinuousRegister):
    '''DET1: Threshold in duration'''

class PeriphRegMap(RegMap):
    ID     = 0x00, ReadRegister32
    CTRL   = 0x04, R_CTRL
    FRAME  = 0x08, ReadRegister32
    OVERFL = 0x0c, ReadRegister32
    ERR    = 0x10, ReadRegister32
    SYNC   = 0x14, ReadRegister32

    SHAPEON  = 0x18, R_SHAPEON
    SHAPEOFF = 0x1c, R_SHAPEOFF
    DET0TH   = 0x20, R_DET0TH
    DET0DU   = 0x24, R_DET0DU
    DET1TH   = 0x28, R_DET1TH
    DET1DU   = 0x2c, R_DET1DU

a = HostMemAccessor()
#a = DummyAccessor()
r = PeriphRegMap(a, 0x60001000)

import pathlib, subprocess

def runsave():
	subprocess.run(f"{pathlib.Path(__file__).resolve().parents[1]}/detsave.sh")

if __name__ == '__main__':
    conf = {
        '/': {
            'tools.sessions.on': True
        }
    }
    cherrypy.config.update({'server.socket_host': '0.0.0.0', 'server.socket_port': 80})
    cherrypy.quickstart(RegmapWebform(r, posthook=runsave), '/', conf)
