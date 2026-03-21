use crate::Valkyrie;
use crate::common::{last_errno, neg_errno, read_word};
use crate::error::Result;
use crate::logger::Logger;
use crate::os::register_syscall::SubCtx;

use libc::c_int;
use std::mem;
use std::ptr;

#[cfg(target_os = "linux")]
fn write_socklen(vk: &mut Valkyrie, addr: u64, len: libc::socklen_t) -> Result<()> {
    vk.mem.write(&mut vk.uc, addr, &len.to_le_bytes())?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_fd_set(vk: &mut Valkyrie, addr: u64) -> Result<libc::fd_set> {
    let bytes = vk
        .mem
        .read(&mut vk.uc, addr, mem::size_of::<libc::fd_set>())?;
    let mut fd_set: libc::fd_set = unsafe { mem::zeroed() };
    unsafe {
        ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&mut fd_set as *mut libc::fd_set).cast::<u8>(),
            bytes.len(),
        );
    }
    Ok(fd_set)
}

#[cfg(target_os = "linux")]
fn write_fd_set(vk: &mut Valkyrie, addr: u64, fd_set: &libc::fd_set) -> Result<()> {
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (fd_set as *const libc::fd_set).cast::<u8>(),
            mem::size_of::<libc::fd_set>(),
        )
    };
    vk.mem.write(&mut vk.uc, addr, bytes)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_guest_timespec(vk: &mut Valkyrie, addr: u64) -> Result<libc::timespec> {
    let width = (vk.cfg.archsize / 8) as usize;
    Ok(libc::timespec {
        tv_sec: read_word(vk, addr, width)? as libc::time_t,
        tv_nsec: read_word(vk, addr + width as u64, width)? as libc::c_long,
    })
}

#[cfg(target_os = "linux")]
fn read_pselect6_sigmask(vk: &mut Valkyrie, addr: u64) -> Result<Option<libc::sigset_t>> {
    let width = (vk.cfg.archsize / 8) as usize;
    let sigmask_addr = read_word(vk, addr, width)?;
    let sigset_size = read_word(vk, addr + width as u64, width)? as usize;

    if sigmask_addr == 0 || sigset_size == 0 {
        return Ok(None);
    }

    let bytes = vk.mem.read(
        &mut vk.uc,
        sigmask_addr,
        sigset_size.min(mem::size_of::<libc::sigset_t>()),
    )?;
    let mut sigmask: libc::sigset_t = unsafe { mem::zeroed() };
    unsafe {
        ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&mut sigmask as *mut libc::sigset_t).cast::<u8>(),
            bytes.len(),
        );
    }
    Ok(Some(sigmask))
}

pub fn sys_socket(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let domain = sctx.arg0() as c_int;
    let socket_type = sctx.arg1() as c_int;
    let protocol = sctx.arg2() as c_int;

    Logger::debug_cgrey(
        format!("sys_socket(domain={domain}, type={socket_type:#x}, protocol={protocol})"),
        vk.cfg.verbose,
    );

    let fd = unsafe { libc::socket(domain, socket_type, protocol) };
    if fd < 0 {
        return Ok(last_errno());
    }

    Ok(fd as u64)
}

pub fn sys_socketcall(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let call = sctx.arg0();
    let args_addr = sctx.arg1();
    let width = (vk.cfg.archsize / 8) as usize;
    let verbose = vk.cfg.verbose;
    let mut arg =
        |index: u64| -> Result<u64> { read_word(vk, args_addr + index * width as u64, width) };

    Logger::debug_cgrey(
        format!("sys_socketcall(call={call}, args={args_addr:#x})"),
        verbose,
    );

    let args = match call {
        1 => [arg(0)?, arg(1)?, arg(2)?, 0, 0, 0],
        3 => [arg(0)?, arg(1)?, arg(2)?, 0, 0, 0],
        8 => [arg(0)?, arg(1)?, arg(2)?, arg(3)?, 0, 0],
        11 => [arg(0)?, arg(1)?, arg(2)?, arg(3)?, arg(4)?, arg(5)?],
        12 => [arg(0)?, arg(1)?, arg(2)?, arg(3)?, arg(4)?, arg(5)?],
        15 => [arg(0)?, arg(1)?, arg(2)?, arg(3)?, arg(4)?, 0],
        _ => return Ok(neg_errno(libc::ENOSYS)),
    };

    let mut subctx = SubCtx::new(args);
    match call {
        1 => sys_socket(vk, &mut subctx),
        3 => sys_connect(vk, &mut subctx),
        8 => sys_socketpair(vk, &mut subctx),
        11 => sys_sendto(vk, &mut subctx),
        12 => sys_recvfrom(vk, &mut subctx),
        15 => sys_getsockopt(vk, &mut subctx),
        _ => Ok(neg_errno(libc::ENOSYS)),
    }
}

pub fn sys_socketpair(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let domain = sctx.arg0() as c_int;
    let socket_type = sctx.arg1() as c_int;
    let protocol = sctx.arg2() as c_int;
    let sv_addr = sctx.arg3();

    if sv_addr == 0 {
        return Ok(neg_errno(libc::EFAULT));
    }

    Logger::debug_cgrey(
        format!(
            "sys_socketpair(domain={domain}, type={socket_type:#x}, protocol={protocol}, sv={sv_addr:#x})"
        ),
        vk.cfg.verbose,
    );

    let mut sv = [0i32; 2];
    let rc = unsafe { libc::socketpair(domain, socket_type, protocol, sv.as_mut_ptr()) };
    if rc < 0 {
        return Ok(last_errno());
    }

    vk.mem.write(&mut vk.uc, sv_addr, &sv[0].to_le_bytes())?;
    vk.mem
        .write(&mut vk.uc, sv_addr + 4, &sv[1].to_le_bytes())?;
    Ok(0)
}

pub fn sys_connect(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0() as c_int;
    let addr_ptr = sctx.arg1();
    let addr_len = sctx.arg2() as libc::socklen_t;

    if addr_ptr == 0 {
        return Ok(neg_errno(libc::EFAULT));
    }

    let addr = vk.mem.read(&mut vk.uc, addr_ptr, addr_len as usize)?;

    Logger::debug_cgrey(
        format!("sys_connect(fd={fd}, addr_ptr={addr_ptr:#x}, addr_len={addr_len})"),
        vk.cfg.verbose,
    );

    let ret = unsafe { libc::connect(fd, addr.as_ptr().cast::<libc::sockaddr>(), addr_len) };
    if ret < 0 {
        return Ok(last_errno());
    }

    Ok(ret as u64)
}

pub fn sys_getsockopt(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0() as c_int;
    let level = sctx.arg1() as c_int;
    let optname = sctx.arg2() as c_int;
    let optval_addr = sctx.arg3();
    let optlen_addr = sctx.arg4();

    if optlen_addr == 0 {
        return Ok(neg_errno(libc::EFAULT));
    }

    Logger::debug_cgrey(
        format!(
            "sys_getsockopt(fd={fd}, level={level}, optname={optname}, optval={optval_addr:#x}, optlen={optlen_addr:#x})"
        ),
        vk.cfg.verbose,
    );

    let optlen_bytes = vk
        .mem
        .read(&mut vk.uc, optlen_addr, mem::size_of::<libc::socklen_t>())?;
    let mut optlen_buf = [0u8; mem::size_of::<libc::socklen_t>()];
    optlen_buf.copy_from_slice(&optlen_bytes);
    let mut optlen = libc::socklen_t::from_le_bytes(optlen_buf);

    if optlen > 0 && optval_addr == 0 {
        return Ok(neg_errno(libc::EFAULT));
    }

    let mut optval = vec![0u8; optlen as usize];
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            optname,
            if optlen > 0 {
                optval.as_mut_ptr().cast::<libc::c_void>()
            } else {
                ptr::null_mut()
            },
            &mut optlen as *mut libc::socklen_t,
        )
    };
    if rc < 0 {
        return Ok(last_errno());
    }

    if optlen > 0 {
        vk.mem
            .write(&mut vk.uc, optval_addr, &optval[..optlen as usize])?;
    }
    write_socklen(vk, optlen_addr, optlen)?;

    Ok(0)
}

pub fn sys_sendto(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0() as c_int;
    let buf_addr = sctx.arg1();
    let len = sctx.arg2() as usize;
    let flags = sctx.arg3() as c_int;
    let dest_addr = sctx.arg4();
    let addr_len = sctx.arg5() as libc::socklen_t;

    let buffer = vk.mem.read(&mut vk.uc, buf_addr, len)?;
    let dest = if dest_addr == 0 || addr_len == 0 {
        None
    } else {
        Some(vk.mem.read(&mut vk.uc, dest_addr, addr_len as usize)?)
    };

    Logger::debug_cgrey(
        format!("sys_sendto(fd={fd}, len={len}, flags={flags:#x})"),
        vk.cfg.verbose,
    );

    let (addr_ptr, addr_len) = match dest.as_ref() {
        Some(addr) => (addr.as_ptr().cast::<libc::sockaddr>(), addr_len),
        None => (ptr::null(), 0),
    };

    let ret = unsafe {
        libc::sendto(
            fd,
            buffer.as_ptr().cast::<libc::c_void>(),
            len,
            flags,
            addr_ptr,
            addr_len,
        )
    };
    if ret < 0 {
        return Ok(last_errno());
    }

    Ok(ret as u64)
}

pub fn sys_recvfrom(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0() as c_int;
    let buf_addr = sctx.arg1();
    let len = sctx.arg2() as usize;
    let flags = sctx.arg3() as c_int;
    let src_addr = sctx.arg4();
    let addrlen_ptr = sctx.arg5();

    let mut buffer = vec![0u8; len];

    Logger::debug_cgrey(
        format!("sys_recvfrom(fd={fd}, len={len}, flags={flags:#x})"),
        vk.cfg.verbose,
    );

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (src_addr, addrlen_ptr);
        return Ok(neg_errno(libc::ENOSYS));
    }

    #[cfg(target_os = "linux")]
    {
        let mut peer_addr = vec![0u8; 128];
        let mut peer_len = peer_addr.len() as libc::socklen_t;
        let (addr_ptr, len_ptr): (*mut libc::sockaddr, *mut libc::socklen_t) =
            if src_addr != 0 && addrlen_ptr != 0 {
                (
                    peer_addr.as_mut_ptr().cast::<libc::sockaddr>(),
                    &mut peer_len as *mut libc::socklen_t,
                )
            } else {
                (ptr::null_mut(), ptr::null_mut())
            };

        let ret = unsafe {
            libc::recvfrom(
                fd,
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                len,
                flags,
                addr_ptr,
                len_ptr,
            )
        };
        if ret < 0 {
            return Ok(last_errno());
        }

        let ret = ret as usize;
        if ret > 0 {
            vk.mem.write(&mut vk.uc, buf_addr, &buffer[..ret])?;
        }

        if src_addr != 0 && addrlen_ptr != 0 {
            let copy_len = (peer_len as usize).min(peer_addr.len());
            if copy_len > 0 {
                vk.mem.write(&mut vk.uc, src_addr, &peer_addr[..copy_len])?;
            }
            write_socklen(vk, addrlen_ptr, peer_len)?;
        }

        Ok(ret as u64)
    }
}

pub fn sys_pselect6(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let nfds = sctx.arg0() as c_int;
    let readfds_addr = sctx.arg1();
    let writefds_addr = sctx.arg2();
    let exceptfds_addr = sctx.arg3();
    let timeout_addr = sctx.arg4();
    let sigmask_addr = sctx.arg5();

    if nfds < 0 {
        return Ok(neg_errno(libc::EINVAL));
    }

    Logger::debug_cgrey(
        format!(
            "sys_pselect6(nfds={nfds}, readfds={readfds_addr:#x}, writefds={writefds_addr:#x}, exceptfds={exceptfds_addr:#x}, timeout={timeout_addr:#x}, sigmask={sigmask_addr:#x})"
        ),
        vk.cfg.verbose,
    );

    #[cfg(not(target_os = "linux"))]
    {
        return Ok(neg_errno(libc::ENOSYS));
    }

    #[cfg(target_os = "linux")]
    {
        let mut readfds = if readfds_addr != 0 {
            Some(read_fd_set(vk, readfds_addr)?)
        } else {
            None
        };
        let mut writefds = if writefds_addr != 0 {
            Some(read_fd_set(vk, writefds_addr)?)
        } else {
            None
        };
        let mut exceptfds = if exceptfds_addr != 0 {
            Some(read_fd_set(vk, exceptfds_addr)?)
        } else {
            None
        };
        let timeout = if timeout_addr != 0 {
            Some(read_guest_timespec(vk, timeout_addr)?)
        } else {
            None
        };
        let sigmask = if sigmask_addr != 0 {
            read_pselect6_sigmask(vk, sigmask_addr)?
        } else {
            None
        };

        let rc = unsafe {
            libc::pselect(
                nfds,
                readfds
                    .as_mut()
                    .map_or(ptr::null_mut(), |fd_set| fd_set as *mut libc::fd_set),
                writefds
                    .as_mut()
                    .map_or(ptr::null_mut(), |fd_set| fd_set as *mut libc::fd_set),
                exceptfds
                    .as_mut()
                    .map_or(ptr::null_mut(), |fd_set| fd_set as *mut libc::fd_set),
                timeout
                    .as_ref()
                    .map_or(ptr::null(), |ts| ts as *const libc::timespec),
                sigmask
                    .as_ref()
                    .map_or(ptr::null(), |set| set as *const libc::sigset_t),
            )
        };
        if rc < 0 {
            return Ok(last_errno());
        }

        if let Some(fd_set) = readfds.as_ref() {
            write_fd_set(vk, readfds_addr, fd_set)?;
        }
        if let Some(fd_set) = writefds.as_ref() {
            write_fd_set(vk, writefds_addr, fd_set)?;
        }
        if let Some(fd_set) = exceptfds.as_ref() {
            write_fd_set(vk, exceptfds_addr, fd_set)?;
        }

        Ok(rc as u64)
    }
}
