from typing import Optional, Dict, Any, List, Tuple
from contextlib import contextmanager

try:
    import unicorn
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False


class MemoryMapper:
    def __init__(self, uc: Optional["unicorn.Uc"]):
        self.uc = uc
        self._mapped_regions: Dict[int, Dict[str, Any]] = {}
        self._next_map_id = 1

    def map(self, name: str, va: int, size: int, 
            read: bool = True, write: bool = True, execute: bool = False,
            content: Optional[bytes] = None) -> bool:
        if not self.uc:
            return False
        
        try:
            perms = 0
            if read:
                perms |= unicorn.UC_PROT_READ
            if write:
                perms |= unicorn.UC_PROT_WRITE
            if execute:
                perms |= unicorn.UC_PROT_EXEC
            
            aligned_va = va & ~0xFFF
            aligned_size = ((size + (va - aligned_va) + 0xFFF) & ~0xFFF)
            
            if va in self._mapped_regions:
                if content:
                    offset = va - aligned_va
                    try:
                        self.uc.mem_write(aligned_va + offset, content[:size])
                    except unicorn.UcError as e:
                        print(f"[DEBUG] memory.map: failed to write content: {e}")
                return True
            
            if self.is_mapped(aligned_va):
                try:
                    test_read = self.uc.mem_read(aligned_va, 1)
                except:
                    self.uc.mem_map(aligned_va, aligned_size, perms)
                else:
                    for reg_va, region in list(self._mapped_regions.items()):
                        if region["aligned_va"] == aligned_va:
                            existing_end = region["aligned_va"] + region["aligned_size"]
                            needed_end = aligned_va + aligned_size
                            if needed_end > existing_end:
                                self.uc.mem_unmap(region["aligned_va"], region["aligned_size"])
                                self.uc.mem_map(aligned_va, aligned_size, perms)
                                del self._mapped_regions[reg_va]
                            break
            else:
                self.uc.mem_map(aligned_va, aligned_size, perms)
            
            if content:
                offset = va - aligned_va
                try:
                    self.uc.mem_write(aligned_va + offset, content[:size])
                except unicorn.UcError as e:
                    print(f"[DEBUG] memory.map: failed to write content: {e}")
            
            self._mapped_regions[va] = {
                "id": self._next_map_id,
                "name": name,
                "va": va,
                "size": size,
                "aligned_va": aligned_va,
                "aligned_size": aligned_size,
                "read": read,
                "write": write,
                "execute": execute,
            }
            self._next_map_id += 1
            
            return True
        except unicorn.UcError as e:
            print(f"Failed to map memory at {hex(va)}: {e}")
            return False

    def map_segment(self, name: str, start_va: int, end_va: int,
                    perm_r: bool, perm_w: bool, perm_x: bool,
                    content: Optional[bytes] = None) -> bool:
        size = end_va - start_va
        return self.map(name, start_va, size, perm_r, perm_w, perm_x, content)

    def unmap(self, va: int) -> bool:
        if not self.uc or va not in self._mapped_regions:
            return False
        
        try:
            region = self._mapped_regions[va]
            self.uc.mem_unmap(region["aligned_va"], region["aligned_size"])
            del self._mapped_regions[va]
            return True
        except unicorn.UcError:
            return False

    def protect(self, va: int, read: bool = True, write: bool = True, 
                execute: bool = False) -> bool:
        if not self.uc or va not in self._mapped_regions:
            return False
        
        try:
            region = self._mapped_regions[va]
            perms = 0
            if read:
                perms |= unicorn.UC_PROT_READ
            if write:
                perms |= unicorn.UC_PROT_WRITE
            if execute:
                perms |= unicorn.UC_PROT_EXEC
            
            self.uc.mem_protect(region["aligned_va"], region["aligned_size"], perms)
            region["read"] = read
            region["write"] = write
            region["execute"] = execute
            return True
        except unicorn.UcError:
            return False

    def read(self, va: int, size: int) -> Optional[bytes]:
        if not self.uc:
            return None
        
        try:
            return self.uc.mem_read(va, size)
        except unicorn.UcError:
            return None

    def write(self, va: int, data: bytes) -> bool:
        if not self.uc:
            return False
        
        try:
            self.uc.mem_write(va, data)
            return True
        except unicorn.UcError:
            return False

    def read_u8(self, va: int) -> Optional[int]:
        data = self.read(va, 1)
        return int.from_bytes(data, 'little') if data else None

    def read_u16(self, va: int) -> Optional[int]:
        data = self.read(va, 2)
        return int.from_bytes(data, 'little') if data else None

    def read_u32(self, va: int) -> Optional[int]:
        data = self.read(va, 4)
        return int.from_bytes(data, 'little') if data else None

    def read_u64(self, va: int) -> Optional[int]:
        data = self.read(va, 8)
        return int.from_bytes(data, 'little') if data else None

    def write_u8(self, va: int, value: int) -> bool:
        return self.write(va, value.to_bytes(1, 'little', signed=False))

    def write_u16(self, va: int, value: int) -> bool:
        return self.write(va, value.to_bytes(2, 'little', signed=False))

    def write_u32(self, va: int, value: int) -> bool:
        return self.write(va, value.to_bytes(4, 'little', signed=False))

    def write_u64(self, va: int, value: int) -> bool:
        return self.write(va, value.to_bytes(8, 'little', signed=False))

    def write_s8(self, va: int, value: int) -> bool:
        return self.write(va, value.to_bytes(1, 'little', signed=True))

    def write_s16(self, va: int, value: int) -> bool:
        return self.write(va, value.to_bytes(2, 'little', signed=True))

    def write_s32(self, va: int, value: int) -> bool:
        return self.write(va, value.to_bytes(4, 'little', signed=True))

    def write_s64(self, va: int, value: int) -> bool:
        return self.write(va, value.to_bytes(8, 'little', signed=True))

    def get_regions(self) -> List[Dict[str, Any]]:
        return list(self._mapped_regions.values())

    def find_free_region(self, size: int, min_va: int = 0x10000, 
                         max_va: int = 0x7FFFFFFF) -> Optional[int]:
        if not self.uc:
            return None
        
        try:
            regions = self.uc.mem_regions()
            used_ranges = [(r.begin, r.end) for r in regions]
            used_ranges.sort()
            
            current = min_va
            for start, end in used_ranges:
                if current + size <= start:
                    return current
                current = max(current, end)
            
            if current + size <= max_va:
                return current
            
            return None
        except:
            return min_va

    @contextmanager
    def mapped(self, name: str, va: int, size: int, 
               read: bool = True, write: bool = True, execute: bool = False,
               content: Optional[bytes] = None):
        self.map(name, va, size, read, write, execute, content)
        try:
            yield
        finally:
            self.unmap(va)

    def is_mapped(self, va: int) -> bool:
        if not self.uc:
            return False
        try:
            self.uc.mem_read(va, 1)
            return True
        except:
            return False

    def get_permissions(self, va: int) -> Optional[Dict[str, bool]]:
        if va not in self._mapped_regions:
            return None
        region = self._mapped_regions[va]
        return {
            "read": region["read"],
            "write": region["write"],
            "execute": region["execute"],
        }

    def allocate_stack(self, base_va: int, size: int) -> int:
        stack_va = base_va - size
        self.map("stack", stack_va, size, read=True, write=True, execute=False)
        return stack_va

    def allocate_heap(self, base_va: int, size: int) -> int:
        self.map("heap", base_va, size, read=True, write=True, execute=False)
        return base_va