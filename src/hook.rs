use std::any::Any;
use std::collections::HashMap;

use unicorn_engine::{
    UcHookId, Unicorn,
    unicorn_const::{HookType, MemType},
};

use crate::error::ValkyrieError;

pub const HOOK_BLOCK: u32 = 1 << 0;

type AnyBox = Box<dyn Any>;
type AnyMut<'a> = &'a mut dyn Any;

type HookCb<C, Args> = Box<dyn FnMut(&mut C, Args, Option<AnyMut<'_>>) -> Option<u32> + 'static>;
type AddrCb<C> = Box<dyn FnMut(&mut C, Option<AnyMut<'_>>) -> Option<u32> + 'static>;

pub struct HookEnv<C> {
    pub ctx: C,
    pub hooks: VCoreHooks<C>,
}

impl<C> HookEnv<C> {
    pub fn new(ctx: C) -> Self {
        Self {
            ctx,
            hooks: VCoreHooks::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookKind {
    Common(HookType), // CODE / BLOCK / INTR / MEM_* / INSN_INVALID ...
    Address(u64),
}

/// Handle user returned
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookRet {
    pub kind: HookKind,
    pub id: u64,
}

type HookId = u64;

struct HookCommon<C, Args> {
    id: HookId,
    begin: u64,
    end: u64,
    user_data: Option<AnyBox>,
    cb: HookCb<C, Args>,
}

struct HookAddr<C> {
    id: HookId,
    #[allow(unused)]
    addr: u64,
    user_data: Option<AnyBox>,
    cb: AddrCb<C>,
}

pub struct VCoreHooks<C> {
    next_id: HookId,
    hook_fuc: HashMap<HookType, UcHookId>, // hook unicorn HookType
    addr_hook_fuc: HashMap<u64, UcHookId>, // hook unicorn hook_address
    hooks: HashMap<HookType, Vec<HookCommon<C, HookArgs>>>, // common hooks  : code/block/mem/intr/invalid
    addr_hooks: HashMap<u64, Vec<HookAddr<C>>>,             // address hooks
}

#[derive(Debug, Clone, Copy)]
pub enum HookArgs {
    Trace {
        addr: u64,
        size: u32,
    },
    Intr {
        intno: u32,
    },
    Mem {
        access: MemType,
        addr: u64,
        size: usize,
        value: i64,
    },
    InvalidInsn,
}

impl<C> VCoreHooks<C> {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            hook_fuc: HashMap::new(),
            addr_hook_fuc: HashMap::new(),
            hooks: HashMap::new(),
            addr_hooks: HashMap::new(),
        }
    }

    fn alloc_id(&mut self) -> HookId {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn bound_check(begin: u64, end: u64, addr: u64) -> bool {
        // adapted from qiling:core_hooks: begin=1 end=0 => full range
        if begin == 1 && end == 0 {
            return true;
        }
        addr >= begin && addr <= end
    }

    // --- Dispatcher installers

    fn ensure_code_dispatcher<'a>(
        &mut self,
        uc: &mut Unicorn<'a, HookEnv<C>>,
    ) -> Result<(), ValkyrieError> {
        let t = HookType::CODE;
        if self.hook_fuc.contains_key(&t) {
            return Ok(());
        }

        let hook_id = uc.add_code_hook(1, 0, move |uc, addr, size| {
            let env_ptr = uc.get_data_mut() as *mut HookEnv<C>;
            unsafe {
                let env = &mut *env_ptr;
                let _ = env
                    .hooks
                    .dispatch_common(&mut env.ctx, t, HookArgs::Trace { addr, size });
            }
        })?;

        self.hook_fuc.insert(t, hook_id);
        Ok(())
    }

    fn ensure_block_dispatcher<'a>(
        &mut self,
        uc: &mut Unicorn<'a, HookEnv<C>>,
    ) -> Result<(), ValkyrieError> {
        let t = HookType::BLOCK;
        if self.hook_fuc.contains_key(&t) {
            return Ok(());
        }

        let hook_id = uc.add_block_hook(1, 0, move |uc, addr, size| {
            let env_ptr = uc.get_data_mut() as *mut HookEnv<C>;
            unsafe {
                let env = &mut *env_ptr;
                let _ = env
                    .hooks
                    .dispatch_common(&mut env.ctx, t, HookArgs::Trace { addr, size });
            }
        })?;

        self.hook_fuc.insert(t, hook_id);
        Ok(())
    }

    fn ensure_intr_dispatcher<'a>(
        &mut self,
        uc: &mut Unicorn<'a, HookEnv<C>>,
    ) -> Result<(), ValkyrieError> {
        let t = HookType::INTR;
        if self.hook_fuc.contains_key(&t) {
            return Ok(());
        }

        let hook_id = uc.add_intr_hook(move |uc, intno| {
            let env_ptr = uc.get_data_mut() as *mut HookEnv<C>;
            unsafe {
                let env = &mut *env_ptr;
                let _ = env
                    .hooks
                    .dispatch_common(&mut env.ctx, t, HookArgs::Intr { intno });
            }
        })?;

        self.hook_fuc.insert(t, hook_id);
        Ok(())
    }

    fn ensure_invalid_insn_dispatcher<'a>(
        &mut self,
        uc: &mut Unicorn<'a, HookEnv<C>>,
    ) -> Result<(), ValkyrieError> {
        let t = HookType::INSN_INVALID;
        if self.hook_fuc.contains_key(&t) {
            return Ok(());
        }

        let hook_id = uc.add_insn_invalid_hook(move |uc| {
            let env_ptr = uc.get_data_mut() as *mut HookEnv<C>;
            unsafe {
                let env = &mut *env_ptr;
                env.hooks
                    .dispatch_common(&mut env.ctx, t, HookArgs::InvalidInsn)
                    .is_ok()
            }
        })?;

        self.hook_fuc.insert(t, hook_id);
        Ok(())
    }

    fn ensure_mem_dispatcher<'a>(
        &mut self,
        uc: &mut Unicorn<'a, HookEnv<C>>,
        t: HookType,
    ) -> Result<(), ValkyrieError> {
        if self.hook_fuc.contains_key(&t) {
            return Ok(());
        }

        let hook_id = uc.add_mem_hook(t, 1, 0, move |uc, access, addr, size, value| {
            let env_ptr = uc.get_data_mut() as *mut HookEnv<C>;
            unsafe {
                let env = &mut *env_ptr;
                env.hooks
                    .dispatch_common(
                        &mut env.ctx,
                        t,
                        HookArgs::Mem {
                            access,
                            addr,
                            size,
                            value,
                        },
                    )
                    .is_ok()
            }
        })?;

        self.hook_fuc.insert(t, hook_id);
        Ok(())
    }

    fn ensure_addr_dispatcher<'a>(
        &mut self,
        uc: &mut Unicorn<'a, HookEnv<C>>,
        address: u64,
    ) -> Result<(), ValkyrieError> {
        if self.addr_hook_fuc.contains_key(&address) {
            return Ok(());
        }

        let hook_id = uc.add_code_hook(address, address, move |uc, addr, _size| {
            let env_ptr = uc.get_data_mut() as *mut HookEnv<C>;
            unsafe {
                let env = &mut *env_ptr;
                let _ = env.hooks.dispatch_addr(&mut env.ctx, addr);
            }
        })?;

        self.addr_hook_fuc.insert(address, hook_id);
        Ok(())
    }

    // --- Dispatcher core ---

    fn dispatch_common(
        &mut self,
        ctx: &mut C,
        hook_type: HookType,
        args: HookArgs,
    ) -> Result<(), ValkyrieError> {
        let mut handled = false;

        if let Some(list) = self.hooks.get_mut(&hook_type) {
            for hook in list.iter_mut() {
                match args {
                    HookArgs::Trace { addr, .. } => {
                        if !Self::bound_check(hook.begin, hook.end, addr) {
                            continue;
                        }
                    }
                    HookArgs::Mem { addr, .. } => {
                        if !Self::bound_check(hook.begin, hook.end, addr) {
                            continue;
                        }
                    }
                    _ => {}
                }

                handled = true;

                let ret = (hook.cb)(ctx, args, hook.user_data.as_deref_mut());
                if matches!(ret, Some(v) if (v & HOOK_BLOCK) != 0) {
                    break;
                }
            }
        }

        let needs_handled = ((hook_type & HookType::MEM_UNMAPPED).0 != 0)
            || ((hook_type & HookType::MEM_PROT).0 != 0)
            || hook_type == HookType::INTR
            || hook_type == HookType::INSN_INVALID;

        if needs_handled && !handled {
            return Err(ValkyrieError::HookNotHandled("event not handled"));
        }

        if needs_handled && !handled {
            return Err(ValkyrieError::HookNotHandled("event not handled"));
        }

        Ok(())
    }

    fn dispatch_addr(&mut self, ctx: &mut C, addr: u64) -> Result<(), ValkyrieError> {
        if let Some(list) = self.addr_hooks.get_mut(&addr) {
            for hook in list.iter_mut() {
                let ret = (hook.cb)(ctx, hook.user_data.as_deref_mut());
                if matches!(ret, Some(v) if (v & HOOK_BLOCK) != 0) {
                    break;
                }
            }
        }
        Ok(())
    }

    // --- Public API ---

    pub fn hook_code<'a, F, U>(
        &mut self,
        uc: &mut Unicorn<'a, HookEnv<C>>,
        callback: F,
        user_data: Option<U>,
        begin: u64,
        end: u64,
    ) -> Result<HookRet, ValkyrieError>
    where
        F: FnMut(&mut C, u64, u32, Option<&mut U>) -> Option<u32> + 'static,
        U: 'static,
    {
        self.ensure_code_dispatcher(uc)?;
        let id = self.alloc_id();

        let ud_box = user_data.map(|u| Box::new(u) as Box<dyn std::any::Any>);
        let mut cb = callback;

        self.hooks
            .entry(HookType::CODE)
            .or_default()
            .push(HookCommon {
                id,
                begin,
                end,
                user_data: ud_box,
                cb: Box::new(move |ctx, args, ud_any| {
                    let HookArgs::Trace { addr, size } = args else {
                        return None;
                    };
                    let ud = ud_any.and_then(|a| a.downcast_mut::<U>());
                    cb(ctx, addr, size, ud)
                }),
            });

        Ok(HookRet {
            kind: HookKind::Common(HookType::CODE),
            id,
        })
    }

    pub fn hook_block<F, U>(
        &mut self,
        uc: &mut Unicorn<HookEnv<C>>,
        callback: F,
        user_data: Option<U>,
        begin: u64,
        end: u64,
    ) -> Result<HookRet, ValkyrieError>
    where
        F: FnMut(&mut C, u64, u32, Option<&mut U>) -> Option<u32> + 'static,
        U: 'static,
    {
        self.ensure_block_dispatcher(uc)?;
        let id = self.alloc_id();

        let ud_box = user_data.map(|u| Box::new(u) as Box<dyn std::any::Any>);
        let mut cb = callback;

        self.hooks
            .entry(HookType::BLOCK)
            .or_default()
            .push(HookCommon {
                id,
                begin,
                end,
                user_data: ud_box,
                cb: Box::new(move |ctx, args, ud_any| {
                    let HookArgs::Trace { addr, size } = args else {
                        return None;
                    };
                    let ud = ud_any.and_then(|a| a.downcast_mut::<U>());
                    cb(ctx, addr, size, ud)
                }),
            });

        Ok(HookRet {
            kind: HookKind::Common(HookType::BLOCK),
            id,
        })
    }

    pub fn hook_intr<F, U>(
        &mut self,
        uc: &mut Unicorn<HookEnv<C>>,
        callback: F,
        user_data: Option<U>,
    ) -> Result<HookRet, ValkyrieError>
    where
        F: FnMut(&mut C, u32, Option<&mut U>) -> Option<u32> + 'static,
        U: 'static,
    {
        self.ensure_intr_dispatcher(uc)?;
        let id = self.alloc_id();

        let ud_box = user_data.map(|u| Box::new(u) as Box<dyn std::any::Any>);
        let mut cb = callback;

        self.hooks
            .entry(HookType::INTR)
            .or_default()
            .push(HookCommon {
                id,
                begin: 1,
                end: 0,
                user_data: ud_box,
                cb: Box::new(move |ctx, args, ud_any| {
                    let HookArgs::Intr { intno } = args else {
                        return None;
                    };
                    let ud = ud_any.and_then(|a| a.downcast_mut::<U>());
                    cb(ctx, intno, ud)
                }),
            });

        Ok(HookRet {
            kind: HookKind::Common(HookType::INTR),
            id,
        })
    }

    pub fn hook_insn_invalid<F, U>(
        &mut self,
        uc: &mut Unicorn<HookEnv<C>>,
        callback: F,
        user_data: Option<U>,
    ) -> Result<HookRet, ValkyrieError>
    where
        F: FnMut(&mut C, Option<&mut U>) -> Option<u32> + 'static,
        U: 'static,
    {
        self.ensure_invalid_insn_dispatcher(uc)?;
        let id = self.alloc_id();

        let ud_box = user_data.map(|u| Box::new(u) as Box<dyn std::any::Any>);
        let mut cb = callback;

        self.hooks
            .entry(HookType::INSN_INVALID)
            .or_default()
            .push(HookCommon {
                id,
                begin: 1,
                end: 0,
                user_data: ud_box,
                cb: Box::new(move |ctx, args, ud_any| {
                    let HookArgs::InvalidInsn = args else {
                        return None;
                    };
                    let ud = ud_any.and_then(|a| a.downcast_mut::<U>());
                    cb(ctx, ud)
                }),
            });

        Ok(HookRet {
            kind: HookKind::Common(HookType::INSN_INVALID),
            id,
        })
    }

    pub fn hook_mem<F, U>(
        &mut self,
        uc: &mut Unicorn<HookEnv<C>>,
        hook_type: HookType,
        callback: F,
        user_data: Option<U>,
        begin: u64,
        end: u64,
    ) -> Result<HookRet, ValkyrieError>
    where
        F: FnMut(&mut C, MemType, u64, usize, i64, Option<&mut U>) -> Option<u32> + 'static,
        U: 'static,
    {
        // hook_type should be READ/WRITE/FETCH/UNMAPPED/PROT/etc.
        self.ensure_mem_dispatcher(uc, hook_type)?;
        let id = self.alloc_id();

        let ud_box = user_data.map(|u| Box::new(u) as Box<dyn std::any::Any>);
        let mut cb = callback;

        self.hooks.entry(hook_type).or_default().push(HookCommon {
            id,
            begin,
            end,
            user_data: ud_box,
            cb: Box::new(move |ctx, args, ud_any| {
                let HookArgs::Mem {
                    access,
                    addr,
                    size,
                    value,
                } = args
                else {
                    return None;
                };
                let ud = ud_any.and_then(|a| a.downcast_mut::<U>());
                cb(ctx, access, addr, size, value, ud)
            }),
        });

        Ok(HookRet {
            kind: HookKind::Common(hook_type),
            id,
        })
    }

    pub fn hook_address<F, U>(
        &mut self,
        uc: &mut Unicorn<HookEnv<C>>,
        address: u64,
        callback: F,
        user_data: Option<U>,
    ) -> Result<HookRet, ValkyrieError>
    where
        F: FnMut(&mut C, Option<&mut U>) -> Option<u32> + 'static,
        U: 'static,
    {
        self.ensure_addr_dispatcher(uc, address)?;
        let id = self.alloc_id();

        let ud_box = user_data.map(|u| Box::new(u) as Box<dyn std::any::Any>);
        let mut cb = callback;

        self.addr_hooks.entry(address).or_default().push(HookAddr {
            id,
            addr: address,
            user_data: ud_box,
            cb: Box::new(move |ctx, ud_any| {
                let ud = ud_any.and_then(|a| a.downcast_mut::<U>());
                cb(ctx, ud)
            }),
        });

        Ok(HookRet {
            kind: HookKind::Address(address),
            id,
        })
    }

    // --- Deletion / clear ---

    pub fn hook_del<'a>(
        &mut self,
        uc: &mut Unicorn<'a, HookEnv<C>>,
        h: HookRet,
    ) -> Result<(), ValkyrieError> {
        match h.kind {
            HookKind::Common(t) => {
                if let Some(list) = self.hooks.get_mut(&t) {
                    list.retain(|x| x.id != h.id);
                    if list.is_empty() {
                        self.hooks.remove(&t);
                        if let Some(uc_handle) = self.hook_fuc.remove(&t) {
                            uc.remove_hook(uc_handle)?;
                        }
                    }
                }
            }
            HookKind::Address(addr) => {
                if let Some(list) = self.addr_hooks.get_mut(&addr) {
                    list.retain(|x| x.id != h.id);
                    if list.is_empty() {
                        self.addr_hooks.remove(&addr);
                        if let Some(uc_handle) = self.addr_hook_fuc.remove(&addr) {
                            uc.remove_hook(uc_handle)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn clear_hooks<'a>(
        &mut self,
        uc: &mut Unicorn<'a, HookEnv<C>>,
    ) -> Result<(), ValkyrieError> {
        for (_, uc_handle) in self.hook_fuc.drain() {
            uc.remove_hook(uc_handle)?;
        }
        for (_, uc_handle) in self.addr_hook_fuc.drain() {
            uc.remove_hook(uc_handle)?;
        }
        self.hooks.clear();
        self.addr_hooks.clear();
        Ok(())
    }
}

impl<C> Default for VCoreHooks<C> {
    fn default() -> Self {
        Self::new()
    }
}
