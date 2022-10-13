import sys
from pymlab import config
from regdefs import *
from server import *

class R_CTRL1(Register16):
	SOFTWARE_RESET = 0

class R_CTRL2(Register16):
	GLOBAL_PDN = 0
	OUTPUT_DISABLE = 1
	PDN_CH0 = 2
	PDN_CH1 = 3
	PDN_CH2 = 4
	PDN_CH3 = 5
	PDN_CH4 = 6
	PDN_CH5 = 7
	PDN_CH6 = 8
	PDN_CH7 = 9

class E_FILTER_BW(IntEnum):
	BW_14MHZ = 0b00
	BW_10MHZ = 0b01
	BW_7M5HZ = 0b10
	BW_UNUSED = 0b11

class R_CTRL8(Register16):
	INTERNAL_AC_COUPLING = 1
	FILTER_BW = 3, 2, E_FILTER_BW
	VCA_LOW_NOISE_MODE = 10

class AFE5801RegMap(RegMap):
	CTRL1 = 0x00, R_CTRL1
	CTRL2 = 0x01, R_CTRL2
	CTRL8 = 0x07, R_CTRL8

cfg = config.Config(
	i2c = {"port": 0, "device": "smbus"},
        bus = [
            {
                "type": "i2chub",
                "address": 0x73,
                "children": [
                    {"name": "i2cspi", "type": "i2cspi" , "channel": 0, "address": 44 },
                ],
            },
        ],
)

cfg.initialize()
i2cspi = cfg.get_device("i2cspi")

class I2CSPIAccessor:
	def write(self, addr, val, width=16):
		assert width == 16
		addr, data = int(addr), int(val)
		bytes = [addr, (data >> 8) & 0xff, data & 0xff]
		i2cspi.SPI_write(0x0f, bytes)

	def read(self, addr, width):
		assert width == 16
		self.write(0x0, 0x2)
		self.write(addr, 0x0)
		ret = i2cspi.SPI_read(3)[1:]
		self.write(0x0, 0x0)
		return ret[0] << 8 | ret[1]

r = AFE5801RegMap(I2CSPIAccessor(), 0)

if __name__ == '__main__':
    conf = {
        '/': {
            'tools.sessions.on': True
        }
    }
    cherrypy.config.update({'server.socket_host': '0.0.0.0', 'server.socket_port': 80})
    cherrypy.quickstart(RegmapWebform(r), '/', conf)
