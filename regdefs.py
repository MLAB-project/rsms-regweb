# 
# Derived from m1n1
# Copyright (c) 2021 The Asahi Linux contributors
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from enum import Enum, IntEnum
import bisect, copy, heapq, importlib, sys, itertools, time, os, functools, struct, re
import mmap

def align_up(v, a=16384):
    return (v + a - 1) & ~(a - 1)

align = align_up

def align_down(v, a=16384):
    return v & ~(a - 1)

class Constant:
    def __init__(self, value):
        self.value = value

    def __call__(self, v):
        assert v == self.value
        return v

class RegisterMeta(type):
    def __new__(cls, name, bases, dct):
        m = super().__new__(cls, name, bases, dct)

        f = {}
        f.update({k: None for k, v in dct.items()
                 if not k.startswith("_") and isinstance(v, (int, tuple))})

        m._fields_list = list(f.keys())
        m._fields = set(f.keys())

        return m

class Register(metaclass=RegisterMeta):
    def __init__(self, v=None, **kwargs):
        if v is not None:
            self._value = v
            for k in self._fields_list:
                getattr(self, k) # validate
        else:
            self._value = 0
            for k in self._fields_list:
                field = getattr(self.__class__, k)
                if isinstance(field, tuple) and len(field) >= 3 and isinstance(field[2], Constant):
                    setattr(self, k, field[2].value)

        for k,v in kwargs.items():
            setattr(self, k, v)

    def __getattribute__(self, attr):
        if attr.startswith("_") or attr not in self._fields:
            return object.__getattribute__(self, attr)

        field = getattr(self.__class__, attr)
        value = self._value

        if isinstance(field, int):
            return (value >> field) & 1
        elif isinstance(field, tuple):
            if len(field) == 2:
                msb, lsb = field
                ftype = int
            else:
                msb, lsb, ftype = field
            return ftype((value >> lsb) & ((1 << ((msb + 1) - lsb)) - 1))
        else:
            raise AttributeError("Invalid field definition %s = %r" % (attr, field))

    def __setattr__(self, attr, fvalue):
        if attr.startswith("_"):
            self.__dict__[attr] = fvalue
            return

        field = getattr(self.__class__, attr)

        value = self._value

        if isinstance(field, int):
            self._value = (value & ~(1 << field)) | ((fvalue & 1) << field)
        elif isinstance(field, tuple):
            if len(field) == 2:
                msb, lsb = field
            else:
                msb, lsb, ftype = field
            mask = ((1 << ((msb + 1) - lsb)) - 1)
            self._value = (value & ~(mask << lsb)) | ((fvalue & mask) << lsb)
        else:
            raise AttributeError("Invalid field definition %s = %r" % (attr, field))

    def __int__(self):
        return self._value

    def _field_val(self, field_name, as_repr=False):
        field = getattr(self.__class__, field_name)
        val = getattr(self, field_name)
        if isinstance(val, Enum):
            if as_repr:
                return str(val)
            else:
                msb, lsb = field[:2]
                if (msb - lsb + 1) > 3:
                    return "0x%x(%s)" % (val.value, val.name)
                else:
                    return "%s(%s)" % (val.value, val.name)
        elif not isinstance(val, int):
            return val
        elif isinstance(field, int):
            return val
        elif isinstance(field, tuple):
            msb, lsb = field[:2]
            if (msb - lsb + 1) > 3:
                return "0x%x" % val

        return val

    @property
    def fields(self):
        return {k: getattr(self, k) for k in self._fields_list}

    def str_fields(self):
        return ', '.join("%s=%s" % (k, self._field_val(k)) for k in self._fields_list)

    def __str__(self):
        return "0x%x(%s)" % (self._value, self.str_fields())
    def __repr__(self):
        return "%s(%s)" % (type(self).__name__, ', '.join("%s=%s" % (k, self._field_val(k, True)) for k in self._fields_list))

    def copy(self):
        return type(self)(self._value)

    @property
    def value(self):
        return self._value
    @value.setter
    def value(self, val):
        self._value = val

class Register8(Register):
    __WIDTH__ = 8

class Register16(Register):
    __WIDTH__ = 16

class Register32(Register):
    __WIDTH__ = 32

class Register64(Register):
    __WIDTH__ = 64

class RangeMap:
    def __init__(self):
        self.__start = []
        self.__end = []
        self.__value = []

    def __len__(self):
        return len(self.__start)

    def __nonzero__(self):
        return bool(self.__start)

    def __contains(self, pos, addr):
        if pos < 0 or pos >= len(self.__start):
            return False

        return self.__start[pos] <= addr and addr <= self.__end[pos]

    def __split(self, pos, addr):
        self.__start.insert(pos + 1, addr)
        self.__end.insert(pos, addr - 1)
        self.__value.insert(pos + 1, copy.copy(self.__value[pos]))

    def __zone(self, zone):
        if isinstance(zone, slice):
            zone = range(zone.start if zone.start is not None else 0,
                         zone.stop if zone.stop is not None else 1 << 64)
        elif isinstance(zone, int):
            zone = range(zone, zone + 1)

        return zone

    def lookup(self, addr, default=None):
        addr = int(addr)

        pos = bisect.bisect_left(self.__end, addr)
        if self.__contains(pos, addr):
            return self.__value[pos]
        else:
            return default

    def __iter__(self):
        return self.ranges()

    def ranges(self):
        return (range(s, e + 1) for s, e in zip(self.__start, self.__end))

    def items(self):
        return ((range(s, e + 1), v) for s, e, v in zip(self.__start, self.__end, self.__value))

    def _overlap_range(self, zone, split=False):
        zone = self.__zone(zone)
        if len(zone) == 0:
            return 0, 0

        start = bisect.bisect_left(self.__end, zone.start)

        if split:
            # Handle left-side overlap
            if self.__contains(start, zone.start) and self.__start[start] != zone.start:
                self.__split(start, zone.start)
                start += 1
                assert self.__start[start] == zone.start

        for pos in range(start, len(self.__start)):
            if self.__start[pos] >= zone.stop:
                return start, pos
            if split and (self.__end[pos] + 1) > zone.stop:
                self.__split(pos, zone.stop)
                return start, pos + 1

        return start, len(self.__start)

    def populate(self, zone, default=[]):
        zone = self.__zone(zone)
        if len(zone) == 0:
            return

        start, stop = zone.start, zone.stop

        # Starting insertion point, overlap inclusive
        pos = bisect.bisect_left(self.__end, zone.start)

        # Handle left-side overlap
        if self.__contains(pos, zone.start) and self.__start[pos] != zone.start:
            self.__split(pos, zone.start)
            pos += 1
            assert self.__start[pos] == zone.start

        # Iterate through overlapping ranges
        while start < stop:
            if pos == len(self.__start):
                # Append to end
                val = copy.copy(default)
                self.__start.append(start)
                self.__end.append(stop - 1)
                self.__value.append(val)
                yield range(start, stop), val
                break

            assert self.__start[pos] >= start
            if self.__start[pos] > start:
                # Insert new range
                boundary = stop
                if pos < len(self.__start):
                    boundary = min(stop, self.__start[pos])
                val = copy.copy(default)
                self.__start.insert(pos, start)
                self.__end.insert(pos, boundary - 1)
                self.__value.insert(pos, val)
                yield range(start, boundary), val
                start = boundary
            else:
                # Handle right-side overlap
                if self.__end[pos] > stop - 1:
                    self.__split(pos, stop)
                # Add to existing range
                yield range(self.__start[pos], self.__end[pos] + 1), self.__value[pos]
                start = self.__end[pos] + 1

            pos += 1
        else:
            assert start == stop

    def overlaps(self, zone, split=False):
        start, stop = self._overlap_range(zone, split)
        for pos in range(start, stop):
            yield range(self.__start[pos], self.__end[pos] + 1), self.__value[pos]

    def replace(self, zone, val):
        zone = self.__zone(zone)
        if zone.start == zone.stop:
            return
        start, stop = self._overlap_range(zone, True)
        self.__start = self.__start[:start] + [zone.start] + self.__start[stop:]
        self.__end = self.__end[:start] + [zone.stop - 1] + self.__end[stop:]
        self.__value = self.__value[:start] + [val] + self.__value[stop:]

    def clear(self, zone=None):
        if zone is None:
            self.__start = []
            self.__end = []
            self.__value = []
        else:
            zone = self.__zone(zone)
            if zone.start == zone.stop:
                return
            start, stop = self._overlap_range(zone, True)
            self.__start = self.__start[:start] + self.__start[stop:]
            self.__end = self.__end[:start] + self.__end[stop:]
            self.__value = self.__value[:start] + self.__value[stop:]

    def compact(self, equal=lambda a, b: a == b, empty=lambda a: not a):
        if len(self) == 0:
            return

        new_s, new_e, new_v = [], [], []

        for pos in range(len(self)):
            s, e, v = self.__start[pos], self.__end[pos], self.__value[pos]
            if empty(v):
                continue
            if new_v and equal(last, v) and s == new_e[-1] + 1:
                new_e[-1] = e
            else:
                new_s.append(s)
                new_e.append(e)
                new_v.append(v)
                last = v

        self.__start, self.__end, self.__value = new_s, new_e, new_v

    def _assert(self, expect, val=lambda a:a):
        state = []
        for i, j, v in zip(self.__start, self.__end, self.__value):
            state.append((i, j, val(v)))
        if state != expect:
            print("Expected: %s" % expect)
            print("Got:      %s" % state)

class SetRangeMap(RangeMap):
    def add(self, zone, key):
        for r, values in self.populate(zone, set()):
            values.add(key)

    def discard(self, zone, key):
        for r, values in self.overlaps(zone, split=True):
            if values:
                values.discard(key)
    remove = discard

    def __setitem__(self, k, value):
        self.replace(k, set(value))

    def __delitem__(self, k):
        self.clear(k)

    def __getitem__(self, addr):
        values = super().lookup(addr)
        return frozenset(values) if values else frozenset()

class NdRange:
    def __init__(self, rng, min_step=1):
        if isinstance(rng, range):
            self.ranges = [rng]
        else:
            self.ranges = list(rng)
        least_step = self.ranges[0].step
        for i, rng in enumerate(self.ranges):
            if rng.step == 1:
                self.ranges[i] = range(rng.start, rng.stop, min_step)
                least_step = min_step
            else:
                assert rng.step >= min_step
                least_step = min(least_step, rng.step)
        self.start = sum(rng[0] for rng in self.ranges)
        self.stop = sum(rng[-1] for rng in self.ranges) + least_step
        self.rev = {}
        for i in itertools.product(*map(enumerate, self.ranges)):
            index = tuple(j[0] for j in i)
            addr = sum(j[1] for j in i)
            if len(self.ranges) == 1:
                index = index[0]
            self.rev[addr] = index

    def index(self, item):
        return self.rev[item]

    def __len__(self):
        return self.stop - self.start

    def __contains__(self, item):
        return item in self.rev

    def __getitem__(self, item):
        if not isinstance(item, tuple):
            assert len(self.ranges) == 1
            return self.ranges[0][item]

        assert len(self.ranges) == len(item)
        if all(isinstance(i, int) for i in item):
            return sum((i[j] for i, j in zip(self.ranges, item)))
        else:
            iters = (i[j] for i, j in zip(self.ranges, item))
            return map(sum, itertools.product(*(([i] if isinstance(i, int) else i) for i in iters)))

class RegMapMeta(type):
    def __new__(cls, name, bases, dct):
        m = super().__new__(cls, name, bases, dct)
        m._addrmap = {}
        m._rngmap = SetRangeMap()
        m._namemap = {}

        for k, v in dct.items():
            if k.startswith("_") or not isinstance(v, tuple):
                continue
            addr, rtype = v

            if isinstance(addr, int):
                m._addrmap[addr] = k, rtype
            else:
                addr = NdRange(addr, rtype.__WIDTH__ // 8)
                m._rngmap.add(addr, (addr, k, rtype))

            m._namemap[k] = addr, rtype

            def prop(k):
                def getter(self):
                    return self._accessor[k]
                def setter(self, val):
                    self._accessor[k].val = val
                return property(getter, setter)

            setattr(m, k, prop(k))

        return m

class RegAccessor:
    def __init__(self, cls, rd, wr, addr):
        self.cls = cls
        self.rd = rd
        self.wr = wr
        self.addr = addr

    def __int__(self):
        return self.rd(self.addr)

    @property
    def val(self):
        return self.rd(self.addr)

    @val.setter
    def val(self, value):
        self.wr(self.addr, int(value))

    @property
    def reg(self):
        val = self.val
        if val is None:
            return None
        return self.cls(val)

    @reg.setter
    def reg(self, value):
        self.wr(self.addr, int(value))

    def set(self, **kwargs):
        r = self.reg
        for k, v in kwargs.items():
            setattr(r, k, v)
        self.wr(self.addr, int(r))

    def __str__(self):
        return str(self.reg)

class RegArrayAccessor:
    def __init__(self, range, cls, rd, wr, addr):
        self.range = range
        self.cls = cls
        self.rd = rd
        self.wr = wr
        self.addr = addr

    def __getitem__(self, item):
        off = self.range[item]
        if isinstance(off, int):
            return RegAccessor(self.cls, self.rd, self.wr, self.addr + off)
        else:
            return [RegAccessor(self.cls, self.rd, self.wr, self.addr + i) for i in off]

class RegMap(metaclass=RegMapMeta):
    def __init__(self, backend, base):
        self._base = base
        self._backend = backend
        self._accessor = {}

        for name, (addr, rcls) in self._namemap.items():
            width = rcls.__WIDTH__
            rd = functools.partial(backend.read, width=width)
            wr = functools.partial(backend.write, width=width)
            if isinstance(addr, NdRange):
                self._accessor[name] = RegArrayAccessor(addr, rcls, rd, wr, base)
            else:
                self._accessor[name] = RegAccessor(rcls, rd, wr, base + addr)

    @classmethod
    def lookup_offset(cls, offset):
        reg = cls._addrmap.get(offset, None)
        if reg is not None:
            name, rcls = reg
            return name, None, rcls
        ret = cls._rngmap[offset]
        if ret:
            for rng, name, rcls in ret:
                if offset in rng:
                    return name, rng.index(offset), rcls
        return None, None, None

    def lookup_addr(self, addr):
        return self.lookup_offset(addr - self._base)

    def get_name(self, addr):
        name, index, rcls = self.lookup_addr(addr)
        if index is not None:
            return "%s[%s]" % (name, index)
        else:
            return name

    @classmethod
    def lookup_name(cls, name):
        return cls._namemap.get(name, None)

    def _scalar_regs(self):
        for addr, (name, rtype) in self._addrmap.items():
            yield addr, name, self._accessor[name], rtype

    def _array_reg(self, zone, map):
        addrs, name, rtype = map
        def index(addr):
            idx = addrs.index(addr)
            if isinstance(idx, tuple):
                idx = str(idx)[1:-1]
            return idx
        reg = ((addr, "%s[%s]" % (name, index(addr)), self._accessor[name][addrs.index(addr)], rtype)
                     for addr in zone if addr in addrs)
        return reg

    def _array_regs(self):
        for zone, maps in self._rngmap.items():
            yield from heapq.merge(*(self._array_reg(zone, map) for map in maps))

    def dump_regs(self):
        for addr, name, acc, rtype in heapq.merge(sorted(self._scalar_regs()), self._array_regs()):
            print("%#x+%06x %s = %x" % (self._base, addr, name, acc.reg))

def irange(start, count, step=1):
    return range(start, start + count * step, step)

