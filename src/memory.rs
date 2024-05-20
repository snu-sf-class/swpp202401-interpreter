use std::{collections::BTreeMap, ops::Bound};

use crate::{
    common::{AccessSize, HEAP_OFFSET, MAX_HEAP_SIZE, MEM_STACK_SIZE, NULL_ADDR},
    error::{SwppErrorKind, SwppRawResult},
};

/// Struct to abstract entire memory, which consists of stack and heap
pub struct SwppMemory {
    /// stack
    stack: [u8; MEM_STACK_SIZE as usize],
    heap: SwppSimpleHeap,
}

impl SwppMemory {
    pub fn get_max_heap_size(&self) -> u64 {
        self.heap.max_size
    }

    pub fn new() -> Self {
        Self {
            stack: [0; MEM_STACK_SIZE as usize],
            heap: SwppSimpleHeap::new(),
        }
    }

    pub fn malloc(&mut self, size: u64) -> SwppRawResult<u64> {
        self.heap.malloc(size)
    }

    pub fn free(&mut self, addr: u64) -> SwppRawResult<()> {
        if addr == NULL_ADDR { return  Ok(());}
        if addr < HEAP_OFFSET {
            return Err(SwppErrorKind::InvalidAddr(addr));
        }

        self.heap.free(addr)
    }

    pub fn read_from_stack(&self, addr: u64, size: AccessSize) -> SwppRawResult<u64> {
        let mut byte_arr = [0; 8];

        for i in 0..size.into() {
            byte_arr[i] = self
                .stack
                .get(addr as usize + i)
                .ok_or(SwppErrorKind::InvalidAddr(addr as u64))?
                .to_owned();
        }
        Ok(u64::from_le_bytes(byte_arr))
    }

    pub fn write_to_stack(&mut self, addr: u64, val: u64, size: AccessSize) -> SwppRawResult<()> {
        let val_bytes = val.to_le_bytes();

        for i in 0..size.into() {
            let target_mem = self
                .stack
                .get_mut(addr as usize + i)
                .ok_or(SwppErrorKind::InvalidAddr(addr as u64))?;
            *target_mem = val_bytes[i];
        }

        Ok(())
    }

    pub fn read_from_heap(&self, addr: u64, size: AccessSize) -> SwppRawResult<u64> {
        self.heap.read(addr, size)
    }

    pub fn write_to_heap(&mut self, addr: u64, val: u64, size: AccessSize) -> SwppRawResult<()> {
        self.heap.write(addr, val, size)
    }

    pub fn print_memory(&self) -> String {
        format!(
            "Stack : {:?}\nHeap:{}",
            self.stack,
            self.heap.print_heap_memory()
        )
    }
}

struct SwppSimpleHeap {
    memory: BTreeMap<u64, Vec<u8>>,
    top_addr: u64,
    max_size: u64,
    cur_size: u64,
}

impl SwppSimpleHeap {
    fn new() -> Self {
        Self {
            memory: BTreeMap::new(),
            top_addr: HEAP_OFFSET,
            max_size: 0,
            cur_size: 0,
        }
    }

    fn print_heap_memory(&self) -> String {
        format!("{:?}", self.memory)
    }

    fn malloc(&mut self, size: u64) -> SwppRawResult<u64> {
        if size + self.top_addr > MAX_HEAP_SIZE {
            return Err(SwppErrorKind::NOMEMHEAP);
        }

        self.memory.insert(self.top_addr, vec![0; size as usize]);

        let old_addr = self.top_addr;
        self.top_addr += size;

        self.cur_size += size;
        self.max_size = self.max_size.max(self.cur_size);

        Ok(old_addr)
    }

    fn free(&mut self, addr: u64) -> SwppRawResult<()> {
        let end_addr = self
            .memory
            .remove(&addr)
            .ok_or(SwppErrorKind::InvalidAddr(addr))?;

        self.cur_size -= end_addr.len() as u64;

        Ok(())
    }

    fn read(&self, addr: u64, size: AccessSize) -> SwppRawResult<u64> {
        let (target_start, target_mem) = self
            .memory
            .range((Bound::Included(HEAP_OFFSET), Bound::Included(addr)))
            .last()
            .ok_or(SwppErrorKind::InvalidAddr(addr))?;

        if (target_start + target_mem.len() as u64) < addr {
            return Err(SwppErrorKind::InvalidAddr(addr));
        }

        let idx = (addr - target_start) as usize;

        let mut byte_arr = [0; 8];
        for i in 0..size.into() {
            byte_arr[i] = target_mem
                .get(idx + i)
                .ok_or(SwppErrorKind::InvalidAddr(addr))?
                .to_owned();
        }
        Ok(u64::from_le_bytes(byte_arr))
    }

    fn write(&mut self, addr: u64, val: u64, size: AccessSize) -> SwppRawResult<()> {
        let (target_start, target_mem) = self
            .memory
            .range_mut((Bound::Included(HEAP_OFFSET), Bound::Included(addr)))
            .last()
            .ok_or(SwppErrorKind::InvalidAddr(addr))?;

        if (target_start + target_mem.len() as u64) < addr {
            return Err(SwppErrorKind::InvalidAddr(addr));
        }

        let idx = (addr - target_start) as usize;
        let val_bytes = val.to_le_bytes();

        for i in 0..size.into() {
            let target_byte = target_mem
                .get_mut(idx + i)
                .ok_or(SwppErrorKind::InvalidAddr(addr))?;
            *target_byte = val_bytes[i];
        }

        Ok(())
    }
}

// struct SwppMemHeap {
//     /// 시작주소 -> allocated 된 공간의 끝 주소
//     alloc_frag_map: BTreeMap<u64, u64>,
//     /// 시작주소 -> empty인 consecutive인 공간의 끝 주소
//     empty_frag_map: BTreeMap<u64, u64>,
//     /// 실질적으로 값을 저장하는곳
//     value_map: HashMap<u64, Vec<u8>>,
// }

// impl SwppMemHeap {
//     fn new() -> Self {
//         Self {
//             alloc_frag_map: BTreeMap::new(),
//             empty_frag_map: BTreeMap::from([(0, u64::MAX)]),
//             value_map: HashMap::new(),
//         }
//     }

//     fn malloc(&mut self, size: u64) -> SwppRawResult<u64> {
//         // 힙에 빈공간이 없다면?
//         if self.empty_frag_map.is_empty() {
//             return Err(SwppErrorKind::NOMEMHEAP);
//         }

//         // target_addr는 이번에 할당할 곳이다.
//         let mut target_addr = None;
//         for (start_addr, last_addr) in &self.empty_frag_map {
//             let frag_size = last_addr - start_addr;
//             if size <= frag_size {
//                 target_addr = Some((*start_addr, *last_addr));
//             }
//         }

//         if let Some((start, last)) = target_addr {
//             let _target_frag = self
//                 .empty_frag_map
//                 .remove(&start)
//                 .expect(INTERNAL_ERROR_MSG);
//             self.empty_frag_map.insert(start + size, last);
//             self.alloc_frag_map.insert(start, start + size - 1);

//             self.value_map.insert(start, vec![0; size as usize]);
//             Ok(start)
//         } else {
//             Err(SwppErrorKind::NOMEMHEAP)
//         }
//     }

//     pub fn free(&mut self, addr: u64) -> SwppRawResult<()> {
//         let mut new_freeblock_start = addr;

//         self.value_map
//             .remove(&addr)
//             .ok_or(SwppErrorKind::InvalidAddr(addr))?;

//         let last_addr = self
//             .alloc_frag_map
//             .remove(&addr)
//             .ok_or(SwppErrorKind::InvalidAddr(addr))?;

//         let mut new_freeblock_end = last_addr;

//         // (addr, last_addr) 만큼을 free로 바꿔줘야함
//         // 먼저 addr를 마지막으로 하는 free frag가 있는지 확인
//         let pre_block = self.empty_frag_map.range(..addr).last();

//         if let Some((pre_start, pre_end)) = pre_block {
//             if *pre_end == addr {
//                 new_freeblock_start = *pre_start;
//             }
//         }

//         // last_addr로 시작하는 free frag가 있는지 확인

//         if let Some(post_end) = self.empty_frag_map.get(&new_freeblock_end).copied() {
//             self.empty_frag_map.remove(&new_freeblock_end);
//             new_freeblock_end = post_end;
//         }

//         self.empty_frag_map
//             .entry(new_freeblock_start)
//             .and_modify(|v| *v = new_freeblock_end);

//         Ok(())
//     }
// }
