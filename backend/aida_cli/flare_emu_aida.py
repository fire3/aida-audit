import logging
import struct
import flare_emu
from binary_database import BinaryDatabase
import io

class AidaBasicBlock:
    def __init__(self, block_id, start_ea, end_ea, type, successors_ids, helper):
        self.id = block_id
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.type = type
        self._successors_ids = successors_ids
        self.helper = helper

    def succs(self):
        # We need to return block objects, not just IDs.
        # This requires the helper to fetch them.
        return [self.helper.get_block_by_id(bid) for bid in self._successors_ids]

class AidaAnalysisHelper(flare_emu.AnalysisHelper):
    def __init__(self, db_path, eh=None):
        super(AidaAnalysisHelper, self).__init__()
        self.eh = eh
        self.db = BinaryDatabase(db_path)
        self.db.connect()
        self.logger = logging.getLogger(__name__)
        
        # Caches
        self._segments = None
        self._sections = None
        self._seg_content = {} # seg_id -> bytes
        self._meta = None
        self._block_cache = {} # block_id -> AidaBasicBlock
        self._func_cache = {} # va -> func_row
        self._insn_cache = {} # va -> (mnem, size, sp_delta)
        
        self._load_metadata()

    def _load_metadata(self):
        self.db.cursor.execute("SELECT content FROM metadata_json WHERE id=1")
        row = self.db.cursor.fetchone()
        if row:
            import json
            self._meta = json.loads(row[0])
            
        # Determine architecture
        if self._meta:
            arch = self._meta.get("arch", "32-bit")
            if "64" in arch:
                self.bitness = 64
                self.arch = "X86" # Assumption, need better check from meta processor
            else:
                self.bitness = 32
                self.arch = "X86"
                
            proc = self._meta.get("processor", "metapc")
            if "arm" in proc.lower():
                self.arch = "ARM"
                if self.bitness == 64:
                    self.arch = "ARM64"
            elif "pc" in proc.lower():
                self.arch = "X86"
                
            fmt = self._meta.get("format", "PE")
            if "PE" in fmt: self.filetype = "PE"
            elif "ELF" in fmt: self.filetype = "ELF"
            elif "Mach" in fmt: self.filetype = "MACHO"
            else: self.filetype = "UNKNOWN"
            
    def get_block_by_id(self, block_id):
        if block_id in self._block_cache:
            return self._block_cache[block_id]
            
        self.db.cursor.execute("SELECT block_id, function_va, start_va, end_va, type FROM basic_blocks WHERE block_id=?", (block_id,))
        row = self.db.cursor.fetchone()
        if not row: return None
        
        # Get successors
        self.db.cursor.execute("SELECT dst_block_id FROM basic_block_successors WHERE src_block_id=?", (block_id,))
        succs = [r[0] for r in self.db.cursor.fetchall()]
        
        bb = AidaBasicBlock(row[0], row[2], row[3], row[4], succs, self)
        self._block_cache[block_id] = bb
        return bb

    def getFuncStart(self, addr):
        self.db.cursor.execute("SELECT start_va FROM functions WHERE start_va <= ? AND end_va > ? ORDER BY start_va DESC LIMIT 1", (addr, addr))
        row = self.db.cursor.fetchone()
        return row[0] if row else None

    def getFuncEnd(self, addr):
        self.db.cursor.execute("SELECT end_va FROM functions WHERE start_va <= ? AND end_va > ? ORDER BY start_va DESC LIMIT 1", (addr, addr))
        row = self.db.cursor.fetchone()
        return row[0] if row else None

    def getFuncName(self, addr, normalized=True):
        self.db.cursor.execute("SELECT name FROM functions WHERE start_va = ?", (addr,))
        row = self.db.cursor.fetchone()
        if row:
            name = row[0]
            if normalized:
                return self.normalizeFuncName(name)
            return name
        return None

    def _get_insn(self, addr):
        if addr in self._insn_cache:
            return self._insn_cache[addr]
        
        self.db.cursor.execute("SELECT mnemonic, size, sp_delta FROM instructions WHERE address=?", (addr,))
        row = self.db.cursor.fetchone()
        if row:
            self._insn_cache[addr] = row
            return row
        return None

    def getMnem(self, addr):
        insn = self._get_insn(addr)
        return insn[0] if insn else ""

    def getInsnSize(self, addr):
        insn = self._get_insn(addr)
        return insn[1] if insn else 1 # Default to 1 to avoid stuck loops

    def getSpDelta(self, addr):
        insn = self._get_insn(addr)
        return insn[2] if insn else 0

    def getFlowChart(self, addr):
        # addr is usually function start
        func_start = self.getFuncStart(addr)
        if func_start is None: return []
        
        self.db.cursor.execute("SELECT block_id FROM basic_blocks WHERE function_va=?", (func_start,))
        block_ids = [r[0] for r in self.db.cursor.fetchall()]
        
        return [self.get_block_by_id(bid) for bid in block_ids]

    def _getBlockByAddr(self, addr, flowchart):
        for bb in flowchart:
            if (addr >= bb.start_ea and addr < bb.end_ea):
                return bb
        return None

    def getBlockEndInsnAddr(self, addr, flowchart):
        bb = self._getBlockByAddr(addr, flowchart)
        if not bb: return None
        # Previous instruction from end_ea
        # We need to query instructions to find the one before end_ea
        self.db.cursor.execute("SELECT address FROM instructions WHERE address < ? ORDER BY address DESC LIMIT 1", (bb.end_ea,))
        row = self.db.cursor.fetchone()
        return row[0] if row else None

    def getMinimumAddr(self):
        self.db.cursor.execute("SELECT MIN(start_va) FROM segments")
        row = self.db.cursor.fetchone()
        return row[0] if row else 0

    def getMaximumAddr(self):
        self.db.cursor.execute("SELECT MAX(end_va) FROM segments")
        row = self.db.cursor.fetchone()
        return row[0] if row else 0xffffffffffffffff

    def _ensure_segments(self):
        if self._segments is None:
            self.db.cursor.execute("SELECT seg_id, start_va, end_va, name FROM segments")
            self._segments = self.db.cursor.fetchall()

    def getBytes(self, addr, size):
        self._ensure_segments()
        # Find segment containing addr
        for seg in self._segments:
            seg_id, start, end, name = seg
            if start <= addr < end:
                # Check cache
                if seg_id not in self._seg_content:
                    self.db.cursor.execute("SELECT content FROM segment_content WHERE seg_id=?", (seg_id,))
                    row = self.db.cursor.fetchone()
                    if row:
                        self._seg_content[seg_id] = row[0]
                    else:
                        self._seg_content[seg_id] = b""
                
                content = self._seg_content[seg_id]
                offset = addr - start
                if offset < len(content):
                    return content[offset:offset+size]
                return None
        return None

    def getCString(self, addr):
        buf = b""
        # Inefficient but simple
        while True:
            b = self.getBytes(addr, 1)
            if not b or b == b"\x00":
                break
            buf += b
            addr += 1
        return buf.decode('utf-8', errors='ignore')

    def getOperand(self, addr, opndNum):
        self.db.cursor.execute("SELECT text FROM instruction_operands WHERE address=? AND op_index=?", (addr, opndNum))
        row = self.db.cursor.fetchone()
        return row[0] if row else ""

    def getOpndType(self, addr, opndNum):
        self.db.cursor.execute("SELECT type FROM instruction_operands WHERE address=? AND op_index=?", (addr, opndNum))
        row = self.db.cursor.fetchone()
        return row[0] if row else -1

    def getOpndValue(self, addr, opndNum):
        self.db.cursor.execute("SELECT value FROM instruction_operands WHERE address=? AND op_index=?", (addr, opndNum))
        row = self.db.cursor.fetchone()
        return row[0] if row else 0

    def getWordValue(self, addr):
        b = self.getBytes(addr, 2)
        if b and len(b) == 2:
            return struct.unpack("<H", b)[0] # Assume little endian for now
        return 0

    def getDwordValue(self, addr):
        b = self.getBytes(addr, 4)
        if b and len(b) == 4:
            return struct.unpack("<I", b)[0]
        return 0

    def getQWordValue(self, addr):
        b = self.getBytes(addr, 8)
        if b and len(b) == 8:
            return struct.unpack("<Q", b)[0]
        return 0

    def isThumbMode(self, addr):
        # Not easily supported yet without processor status export
        return False

    def getSegmentName(self, addr):
        self._ensure_segments()
        for seg in self._segments:
            if seg[1] <= addr < seg[2]:
                return seg[3]
        return ""

    def getSegmentStart(self, addr):
        self._ensure_segments()
        for seg in self._segments:
            if seg[1] <= addr < seg[2]:
                return seg[1]
        return 0

    def getSegmentEnd(self, addr):
        self._ensure_segments()
        for seg in self._segments:
            if seg[1] <= addr < seg[2]:
                return seg[2]
        return 0
        
    def getSegmentDefinedSize(self, addr):
        # We assume content length is defined size
        self._ensure_segments()
        for seg in self._segments:
             if seg[1] <= addr < seg[2]:
                 seg_id = seg[0]
                 if seg_id not in self._seg_content:
                      self.db.cursor.execute("SELECT content FROM segment_content WHERE seg_id=?", (seg_id,))
                      row = self.db.cursor.fetchone()
                      if row:
                          self._seg_content[seg_id] = row[0]
                      else:
                          self._seg_content[seg_id] = b""
                 return len(self._seg_content[seg_id])
        return 0

    def getSegments(self):
        self._ensure_segments()
        return [seg[1] for seg in self._segments] # Return start addresses? flare_emu expects objects or list?
        # flare_emu_ida uses idautils.Segments() which returns start addresses.
        
    def getDisasmLine(self, addr):
        self.db.cursor.execute("SELECT content FROM disasm_chunks WHERE start_va <= ? AND end_va > ? LIMIT 1", (addr, addr))
        row = self.db.cursor.fetchone()
        # This returns a chunk. We need to parse line?
        # Actually we should store line by line or parse it.
        # But instructions table has mnem.
        # flare_emu uses getDisasmLine for comments and searching "pop pc" etc.
        # If we have instructions, we can reconstruct it.
        mnem = self.getMnem(addr)
        ops = []
        for i in range(8):
             op = self.getOperand(addr, i)
             if not op: break
             ops.append(op)
        return f"{mnem} {', '.join(ops)}"

    def getName(self, addr):
        # Symbol or function name
        name = self.getFuncName(addr, normalized=False)
        if name: return name
        self.db.cursor.execute("SELECT name FROM symbols WHERE address=?", (addr,))
        row = self.db.cursor.fetchone()
        return row[0] if row else ""

    def getNameAddr(self, name):
        self.db.cursor.execute("SELECT start_va FROM functions WHERE name=?", (name,))
        row = self.db.cursor.fetchone()
        if row: return row[0]
        self.db.cursor.execute("SELECT address FROM symbols WHERE name=?", (name,))
        row = self.db.cursor.fetchone()
        return row[0] if row else None

    def getXrefsTo(self, addr):
        self.db.cursor.execute("SELECT from_va FROM xrefs WHERE to_va=?", (addr,))
        return [r[0] for r in self.db.cursor.fetchall()]

    def getArch(self):
        return self.arch

    def getBitness(self):
        return self.bitness

    def getFileType(self):
        return self.filetype

    def isTerminatingBB(self, bb):
        # Type logic. IDA types:
        # fcb_normal=0, fcb_indjump=1, fcb_ret=2, fcb_cndret=3, fcb_noret=4, fcb_enoret=5, fcb_extern=6, fcb_error=7
        if bb.type in [2, 4, 6]: # ret, noret, extern
            return True
        if bb.type == 1 and not bb.succs(): # indjump with no successors
            return True
        return False
        
    def normalizeFuncName(self, funcName):
        import re
        if not funcName: return ""
        if funcName.startswith("sub_") or funcName.startswith("loc_"):
            return funcName
        funcName = re.sub(r"_[\d]+$", "", funcName)
        return funcName

    # Modification methods - no-op for now
    def makeInsn(self, addr): pass
    def createFunction(self, addr): pass
    def setName(self, addr, name, size=0): pass
    def setComment(self, addr, comment, repeatable=False): pass


class AidaEmuHelper(flare_emu.EmuHelper):
    def __init__(self, db_path, verbose=0):
        # Initialize basic stuff
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)
        self.stack = 0
        self.stackSize = 0x8000
        self.size_DWORD = 4
        self.size_pointer = 0
        self.callMnems = ["CALL", "BL", "BLX", "BLR", "BLXEQ", "BLEQ", "BLREQ"]
        self.paths = {}
        self.filetype = "UNKNOWN"
        self.uc = None
        self.h_userhook = None
        self.h_memaccesshook = None
        self.h_codehook = None
        self.h_memhook = None
        self.h_inthook = None
        self.enteredBlock = False
        self.hookData = {}
        
        # Use our helper
        self.analysisHelper = AidaAnalysisHelper(db_path, self)
        self.analysisHelperFramework = "AIDA"
        
        # Determine bitness/arch from helper to set size_pointer
        if self.analysisHelper.getBitness() == 64:
             self.size_pointer = 8
             self.pack_fmt = "<Q"
             self.pack_fmt_signed = "<q"
        else:
             self.size_pointer = 4
             self.pack_fmt = "<I"
             self.pack_fmt_signed = "<i"
             
        self.initEmuHelper()
        self.reloadBinary()
