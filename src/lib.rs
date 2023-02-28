/*
 * Copyright 2022 Oxide Computer Company
 * Copyright 2022 OpenFlowLabs
 */

use anyhow::{anyhow, bail, Context, Result};
use log::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub mod ensure;
pub mod expand;
pub mod fmri;
pub mod illumos;
pub mod lofi;

use ensure::Create;
use expand::Expansion;

pub type Build = fn(ib: &mut ImageBuilder) -> Result<()>;

/*
 * Hard-coded user ID and group ID for root:
 */
pub const ROOT: u32 = 0;

/*
 * We cannot correctly use the name service switch to translate user IDs for use
 * in the target image, as the database within the target may not match the
 * build system.  For now, assume we only need to deal with a handful of
 * hard-coded user names.
 */
pub fn translate_uid(user: &str) -> Result<u32> {
    Ok(match user {
        "root" => ROOT,
        "daemon" => 1,
        "bin" => 2,
        "sys" => 3,
        "adm" => 4,
        n => bail!("unknown user \"{}\"", n),
    })
}

/*
 * The situation is the same for group IDs as it is for user IDs.  See comments
 * for translate_uid().
 */
pub fn translate_gid(group: &str) -> Result<u32> {
    Ok(match group {
        "root" => ROOT,
        "other" => 1,
        "bin" => 2,
        "sys" => 3,
        "adm" => 4,
        n => bail!("unknown group \"{}\"", n),
    })
}

/**
 * If a lofi device for this file exists, detach it.  Returns true if a lofi
 * device was found, otherwise returns false.
 */
pub fn teardown_lofi<P: AsRef<Path>>(imagefile: P) -> Result<bool> {
    let imagefile = imagefile.as_ref();

    let lofis = lofi::lofi_list()?;
    let matches: Vec<_> = lofis.iter().filter(|li| li.filename == imagefile).collect();
    if !matches.is_empty() {
        if matches.len() != 1 {
            bail!("too many lofis");
        }

        let li = &matches[0];

        info!("lofi exists {:?} -- removing...", li);
        lofi::lofi_unmap_device(&li.devpath.as_ref().unwrap())?;
        Ok(true)
    } else {
        info!("no lofi found");
        Ok(false)
    }
}

pub fn attach_lofi<P: AsRef<Path>>(imagefile: P, label: bool) -> Result<lofi::LofiDevice> {
    let lofi = lofi::lofi_map(&imagefile, label)?;
    info!("lofi device = {}", lofi.devpath.as_ref().unwrap().display());

    Ok(lofi)
}

/**
 * Create a blank image file of size megabytes and attach it as a lofi(7D)
 * device.  If a lofi device for that file already exists, detach it first.  If
 * the image file already exists, remove it and replace it.  If label is true,
 * create a labelled lofi device (with partitions and slices), otherwise create
 * an unlabelled (simple) device.
 */
pub fn recreate_lofi<P: AsRef<Path>>(
    imagefile: P,
    size: usize,
    label: bool,
) -> Result<lofi::LofiDevice> {
    let imagefile = imagefile.as_ref();

    /*
     * Check to make sure it is not already in lofi:
     */
    teardown_lofi(imagefile)?;

    ensure::removed(imagefile)?;

    /*
     * Create the file that we will use as the backing store for the pool.  The
     * size of this file is the resultant disk image size.
     */
    mkfile(&imagefile, size)?;

    /*
     * Attach this file as a lofi(7D) device.
     */
    attach_lofi(imagefile, label)
}

/**
 * Offset and length (within an ISO image) of an El Torito boot image.  Sizes
 * are in bytes.
 */
#[derive(Debug)]
pub struct ElToritoEntry {
    pub offset: usize,
    pub length: usize,
}

/**
 * Add an MBR partition to the specified raw device.  Valid values for
 * "id" are described in "/usr/include/sys/dktp/fdisk.h"; of particular
 * note:
 *      X86BOOT     190     x86 illumos boot partition
 *      EFI_FS      239     EFI File System (System Partition)
 *
 * Both "start" and "nsectors" are specified as a count of 512 byte disk blocks.
 */
pub fn fdisk_add<P: AsRef<Path>>(rdev: P, id: u8, start: u32, nsectors: u32) -> Result<()> {
    let rdev = rdev.as_ref();

    ensure::run(&[
        "/usr/sbin/fdisk",
        "-A",
        &format!("{}:0:0:0:0:0:0:0:{}:{}", id, start, nsectors),
        rdev.to_str().unwrap(),
    ])?;

    Ok(())
}

pub fn installboot<P1, P2, P3>(rdev: P1, stage1: P2, stage2: P3) -> Result<()>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
    P3: AsRef<Path>,
{
    let rdev = rdev.as_ref();
    let stage1 = stage1.as_ref();
    let stage2 = stage2.as_ref();

    ensure::run(&[
        "/usr/sbin/installboot",
        "-fm",
        stage1.to_str().unwrap(),
        stage2.to_str().unwrap(),
        rdev.to_str().unwrap(),
    ])?;

    Ok(())
}

pub fn etdump<P: AsRef<Path>>(imagefile: P, platform: &str, system: &str) -> Result<ElToritoEntry> {
    let imagefile = imagefile.as_ref();

    info!("examining El Torito entries in {:?}", imagefile);

    let etdump = Command::new("/usr/bin/etdump")
        .env_clear()
        .arg("--format")
        .arg("shell")
        .arg(imagefile)
        .output()?;

    if !etdump.status.success() {
        let errmsg = String::from_utf8_lossy(&etdump.stderr);
        bail!("etdump failed: {}", errmsg);
    }

    for l in String::from_utf8(etdump.stdout)?.lines() {
        let mut m: HashMap<String, String> = HashMap::new();
        for t in l.split(';') {
            let kv = t.split('=').collect::<Vec<_>>();
            if kv.len() != 2 {
                bail!("unexpected term in etdump line: {:?}", l);
            }
            if let Some(k) = kv[0].strip_prefix("et_") {
                m.insert(k.to_string(), kv[1].to_string());
            }
        }

        if m.get("platform") == Some(&platform.to_string())
            && m.get("system") == Some(&system.to_string())
        {
            let offset = if let Some(lba) = m.get("lba") {
                lba.parse::<usize>()? * 2048
            } else {
                bail!("missing LBA?");
            };
            let length = if let Some(sectors) = m.get("sectors") {
                sectors.parse::<usize>()? * 512
            } else {
                bail!("missing sectors?");
            };

            return Ok(ElToritoEntry { offset, length });
        }
    }

    bail!(
        "could not find El Torito entry for (platform {} system {})",
        platform,
        system
    );
}

pub fn find_template_root(arg: Option<String>) -> Result<PathBuf> {
    Ok(if let Some(arg) = arg {
        let p = PathBuf::from(&arg);
        if p.is_relative() {
            let mut cd = std::env::current_dir()?;
            cd.push(&p);
            cd
        } else {
            p
        }
    } else {
        /*
         * If no template root is specified, we default to the natural location:
         * either up one, if we are deployed in a "bin" directory, or up to the
         * project root if we reside in a Cargo "target" directory.
         */
        jmclib::dirs::rootpath("templates")?
    })
}

pub fn gzip<P1, P2>(src: P1, dst: P2) -> Result<()>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
{
    let src = src.as_ref();
    let dst = dst.as_ref();

    info!("GZIP {:?} -> {:?}", src, dst);

    let f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(dst)?;

    let cmd = Command::new("/usr/bin/gzip")
        .env_clear()
        .arg("-c")
        .arg(src)
        .stdout(Stdio::from(f))
        .output()?;

    if !cmd.status.success() {
        let errmsg = String::from_utf8_lossy(&cmd.stderr);
        bail!("gzip {:?} > {:?} failed: {}", src, dst, errmsg);
    }

    info!("gzip ok");

    Ok(())
}

pub fn zpool_set(pool: &str, n: &str, v: &str) -> Result<()> {
    if pool.contains('/') {
        bail!("no / allowed here");
    }

    info!("SET POOL PROPERTY ON {}: {} = {}", pool, n, v);

    let cmd = Command::new("/sbin/zpool")
        .env_clear()
        .arg("set")
        .arg(&format!("{}={}", n, v))
        .arg(pool)
        .output()?;

    if !cmd.status.success() {
        let errmsg = String::from_utf8_lossy(&cmd.stderr);
        bail!("zpool set {} failed: {}", n, errmsg);
    }

    Ok(())
}

pub fn zfs_set(dataset: &str, n: &str, v: &str) -> Result<()> {
    info!("SET DATASET PROPERTY ON {}: {} = {}", dataset, n, v);

    let cmd = Command::new("/sbin/zfs")
        .env_clear()
        .arg("set")
        .arg(&format!("{}={}", n, v))
        .arg(dataset)
        .output()?;

    if !cmd.status.success() {
        let errmsg = String::from_utf8_lossy(&cmd.stderr);
        bail!("zfs set {} failed: {}", n, errmsg);
    }

    Ok(())
}

pub fn zfs_get(dataset: &str, n: &str) -> Result<String> {
    let zfs = Command::new("/sbin/zfs")
        .env_clear()
        .arg("get")
        .arg("-H")
        .arg("-o")
        .arg("value")
        .arg(n)
        .arg(dataset)
        .output()?;

    if !zfs.status.success() {
        let errmsg = String::from_utf8_lossy(&zfs.stderr);
        bail!("zfs get failed: {}", errmsg);
    }

    let out = String::from_utf8(zfs.stdout)?;
    Ok(out.trim().to_string())
}

pub fn dataset_exists(dataset: &str) -> Result<bool> {
    if dataset.contains('@') {
        bail!("no @ allowed here");
    }

    let zfs = Command::new("/sbin/zfs")
        .env_clear()
        .arg("list")
        .arg("-Ho")
        .arg("name")
        .arg(dataset)
        .output()?;

    if !zfs.status.success() {
        let errmsg = String::from_utf8_lossy(&zfs.stderr);
        if errmsg.trim().ends_with("dataset does not exist") {
            return Ok(false);
        }
        bail!("zfs list failed: {}", errmsg);
    }

    Ok(true)
}

pub fn dataset_remove(dataset: &str) -> Result<bool> {
    if dataset.contains('@') {
        bail!("no @ allowed here");
    }

    info!("DESTROY DATASET: {}", dataset);

    let zfs = Command::new("/sbin/zfs")
        .env_clear()
        .arg("destroy")
        .arg("-r")
        .arg(dataset)
        .output()?;

    if !zfs.status.success() {
        let errmsg = String::from_utf8_lossy(&zfs.stderr);
        if errmsg.trim().ends_with("dataset does not exist") {
            return Ok(false);
        }
        bail!("zfs destroy failed: {}", errmsg);
    }

    Ok(true)
}

pub fn pool_destroy(name: &str) -> Result<bool> {
    if name.contains('@') {
        bail!("no @ allowed here");
    }

    info!("DESTROY POOL: {}", name);

    let cmd = Command::new("/sbin/zpool")
        .env_clear()
        .arg("destroy")
        .arg("-f")
        .arg(&name)
        .output()?;

    if !cmd.status.success() {
        let errmsg = String::from_utf8_lossy(&cmd.stderr);
        if errmsg.trim().ends_with("no such pool") {
            return Ok(false);
        }
        bail!("zpool destroy failed: {}", errmsg);
    }

    Ok(true)
}

pub fn pool_export(name: &str) -> Result<bool> {
    if name.contains('@') {
        bail!("no @ allowed here");
    }

    info!("EXPORT POOL: {}", name);

    loop {
        let cmd = Command::new("/sbin/zpool")
            .env_clear()
            .arg("export")
            .arg(&name)
            .output()?;

        if cmd.status.success() {
            break;
        }

        let errmsg = String::from_utf8_lossy(&cmd.stderr);
        if errmsg.trim().ends_with("pool is busy") {
            warn!("pool is busy... retrying...");
            std::thread::sleep(std::time::Duration::from_secs(1));
            continue;
        }
        bail!("zpool export failed: {}", errmsg);
    }

    Ok(true)
}

#[allow(dead_code)]
pub fn snapshot_remove(dataset: &str, snapshot: &str) -> Result<bool> {
    if dataset.contains('@') || snapshot.contains('@') {
        bail!("no @ allowed here");
    }

    let n = format!("{}@{}", dataset, snapshot);
    let zfs = Command::new("/sbin/zfs")
        .env_clear()
        .arg("destroy")
        .arg(&n)
        .output()?;

    if !zfs.status.success() {
        let errmsg = String::from_utf8_lossy(&zfs.stderr);
        if errmsg.trim().ends_with("dataset does not exist") {
            return Ok(false);
        }
        bail!("zfs list failed: {}", errmsg);
    }

    Ok(true)
}

pub fn snapshot_exists(dataset: &str, snapshot: &str) -> Result<bool> {
    if dataset.contains('@') || snapshot.contains('@') {
        bail!("no @ allowed here");
    }

    let n = format!("{}@{}", dataset, snapshot);
    let zfs = Command::new("/sbin/zfs")
        .env_clear()
        .arg("list")
        .arg("-t")
        .arg("snapshot")
        .arg("-Ho")
        .arg("name")
        .arg(&n)
        .output()?;

    if !zfs.status.success() {
        let errmsg = String::from_utf8_lossy(&zfs.stderr);
        if errmsg.trim().ends_with("dataset does not exist") {
            return Ok(false);
        }
        bail!("zfs list failed: {}", errmsg);
    }

    Ok(true)
}

pub fn snapshot_create(dataset: &str, snapshot: &str) -> Result<bool> {
    if dataset.contains('@') || snapshot.contains('@') {
        bail!("no @ allowed here");
    }

    let n = format!("{}@{}", dataset, snapshot);
    info!("CREATE SNAPSHOT: {}", n);

    let zfs = Command::new("/sbin/zfs")
        .env_clear()
        .arg("snapshot")
        .arg(&n)
        .output()?;

    if !zfs.status.success() {
        let errmsg = String::from_utf8_lossy(&zfs.stderr);
        bail!("zfs snapshot failed: {}", errmsg);
    }

    Ok(true)
}

pub fn snapshot_rollback(dataset: &str, snapshot: &str) -> Result<bool> {
    if dataset.contains('@') || snapshot.contains('@') {
        bail!("no @ allowed here");
    }

    let n = format!("{}@{}", dataset, snapshot);
    info!("ROLLBACK TO SNAPSHOT: {}", n);

    let zfs = Command::new("/sbin/zfs")
        .env_clear()
        .arg("rollback")
        .arg("-r")
        .arg(&n)
        .output()?;

    if !zfs.status.success() {
        let errmsg = String::from_utf8_lossy(&zfs.stderr);
        bail!("zfs snapshot failed: {}", errmsg);
    }

    Ok(true)
}

pub fn dataset_clone(snapshot: &str, dataset: &str, opts: Option<Vec<String>>) -> Result<()> {
    if !snapshot.contains('@') {
        bail!("snapshot {} does not seem to be a snapshot", snapshot);
    }

    info!("CLONING SNAPSHOT {} TO DATASET: {}", snapshot, dataset);

    let mut cmd = Command::new("/sbin/zfs");
    cmd.env_clear();
    cmd.arg("clone");

    if let Some(opts) = opts {
        for opt in opts {
            cmd.arg("-o");
            cmd.arg(opt);
        }
    }
    cmd.arg(snapshot);
    cmd.arg(dataset);

    let zfs = cmd.output()?;

    if !zfs.status.success() {
        let errmsg = String::from_utf8_lossy(&zfs.stderr);
        bail!("zfs create failed: {}", errmsg);
    }

    Ok(())
}

pub fn dataset_create(dataset: &str, parents: bool) -> Result<()> {
    if dataset.contains('@') {
        bail!("no @ allowed here");
    }

    info!("CREATE DATASET: {}", dataset);

    let mut cmd = Command::new("/sbin/zfs");
    cmd.env_clear();
    cmd.arg("create");
    if parents {
        cmd.arg("-p");
    }
    cmd.arg(dataset);

    let zfs = cmd.output()?;

    if !zfs.status.success() {
        let errmsg = String::from_utf8_lossy(&zfs.stderr);
        bail!("zfs create failed: {}", errmsg);
    }

    Ok(())
}

pub fn mkfile<P: AsRef<Path>>(filename: P, mblen: usize) -> Result<()> {
    let filename = filename.as_ref();
    info!("CREATE IMAGE ({}MB): {}", mblen, filename.display());

    let cmd = Command::new("/usr/sbin/mkfile")
        .env_clear()
        .arg(&format!("{}m", mblen))
        .arg(filename.as_os_str())
        .output()?;

    if !cmd.status.success() {
        let errmsg = String::from_utf8_lossy(&cmd.stderr);
        bail!("mkfile({}) failed: {}", filename.display(), errmsg);
    }

    Ok(())
}

pub fn pkg(args: &[&str]) -> Result<()> {
    let mut newargs = vec!["/usr/bin/pkg"];
    for arg in args {
        newargs.push(arg);
    }

    ensure::run(&newargs)
}

pub fn pkg_install(root: &str, packages: &[&str]) -> Result<()> {
    let mut newargs = vec!["/usr/bin/pkg", "-R", root, "install"];
    for pkg in packages {
        newargs.push(pkg);
    }

    ensure::run(&newargs)
}

pub fn pkg_uninstall(root: &str, packages: &[&str]) -> Result<()> {
    let mut newargs = vec!["/usr/bin/pkg", "-R", root, "uninstall"];
    for pkg in packages {
        newargs.push(pkg);
    }

    ensure::run(&newargs)
}

pub fn pkg_optional_deps(root: &str, package: &str, strip_publisher: bool) -> Result<Vec<String>> {
    let cmd = Command::new("/usr/bin/pkg")
        .env_clear()
        .arg("-R")
        .arg(root)
        .arg("contents")
        .arg("-t")
        .arg("depend")
        .arg("-a")
        .arg("type=optional")
        .arg("-H")
        .arg("-o")
        .arg("fmri")
        .arg(package)
        .output()?;

    if !cmd.status.success() {
        let errmsg = String::from_utf8_lossy(&cmd.stderr);
        bail!("pkg contents failed: {}", errmsg);
    }

    let out = String::from_utf8(cmd.stdout)?;
    Ok(out
        .lines()
        .map(|s| fmri::Package::parse_fmri(s))
        .collect::<Result<Vec<_>>>()?
        .iter()
        .map(|p| {
            if strip_publisher {
                p.to_string_without_publisher()
            } else {
                p.to_string()
            }
        })
        .collect())
}

pub fn pkg_ensure_variant(root: &str, variant: &str, value: &str) -> Result<()> {
    let cmd = Command::new("/usr/bin/pkg")
        .env_clear()
        .arg("-R")
        .arg(root)
        .arg("variant")
        .arg("-F")
        .arg("json")
        .output()?;

    if !cmd.status.success() {
        let errmsg = String::from_utf8_lossy(&cmd.stderr);
        bail!("pkg variant failed: {}", errmsg);
    }

    #[derive(Deserialize)]
    struct Variant {
        variant: String,
        value: String,
    }

    let tab: Vec<Variant> = serde_json::from_slice(&cmd.stdout)?;
    for ent in tab.iter() {
        if ent.variant == format!("variant.{}", variant) {
            if ent.value == value {
                info!("variant {} is already {}", variant, value);
                return Ok(());
            } else {
                info!(
                    "variant {} is {}; changing to {}",
                    variant, ent.value, value
                );
                break;
            }
        }
    }

    ensure::run(&[
        "/usr/bin/pkg",
        "-R",
        root,
        "change-variant",
        &format!("{}={}", variant, value),
    ])?;
    Ok(())
}

pub fn pkg_ensure_facet(root: &str, facet: &str, value: &str) -> Result<()> {
    let cmd = Command::new("/usr/bin/pkg")
        .env_clear()
        .arg("-R")
        .arg(root)
        .arg("facet")
        .arg("-F")
        .arg("json")
        .output()?;

    if !cmd.status.success() {
        let errmsg = String::from_utf8_lossy(&cmd.stderr);
        bail!("pkg facet failed: {}", errmsg);
    }

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct Facet {
        facet: String,
        masked: String,
        src: String,
        value: String,
    }

    let tab: Vec<Facet> = serde_json::from_slice(&cmd.stdout)?;
    for ent in tab.iter() {
        if ent.facet == format!("facet.{}", facet) {
            if ent.value == value {
                info!("facet {} is already {}", facet, value);
                return Ok(());
            } else {
                info!("facet {} is {}; changing to {}", facet, ent.value, value);
                break;
            }
        }
    }

    ensure::run(&[
        "/usr/bin/pkg",
        "-R",
        root,
        "change-facet",
        &format!("{}={}", facet, value),
    ])?;
    Ok(())
}

pub fn seed_smf(
    svccfg: &str,
    tmpdir: &Path,
    mountpoint: &Path,
    debug: bool,
    apply_site: bool,
) -> Result<()> {
    let tmpdir = tmpdir.to_str().unwrap();
    let mountpoint = mountpoint.to_str().unwrap();

    let dtd = format!("{}/usr/share/lib/xml/dtd/service_bundle.dtd.1", mountpoint);
    let repo = format!("{}/repo.db", tmpdir);
    let seed = format!("{}/lib/svc/seed/{}.db", mountpoint, "global");
    let manifests = format!("{}/lib/svc/manifest", mountpoint);
    let installto = format!("{}/etc/svc/repository.db", mountpoint);

    ensure::file(&seed, &repo, ROOT, ROOT, 0o600, Create::Always)?;

    let mut env = HashMap::new();
    env.insert("SVCCFG_DTD".to_string(), dtd);
    env.insert("SVCCFG_REPOSITORY".to_string(), repo.to_string());
    env.insert("SVCCFG_CHECKHASH".to_string(), "1".to_string());
    env.insert("PKG_INSTALL_ROOT".to_string(), mountpoint.to_string());

    ensure::run_envs(
        &[svccfg, "import", "-p", "/dev/stdout", &manifests],
        Some(&env),
    )?;

    /*
     * If required, smf(5) can generate quite a lot of debug log output.  This
     * output includes diagnostic information about transitions in the service
     * graph, the execution of methods, the management of contracts, etc.
     *
     * This extra debugging can be requested in the boot arguments, via "-m
     * debug", but that presently forces the output to the console which is
     * generally unhelpful.  It is also not possible to set boot arguments
     * in an environment such as AWS where we have no control over the
     * instance console.  Fortunately the logs can be enabled a second way:
     * through smf(5) properties.
     *
     * If requested enable debug logging for this image:
     */
    if debug {
        ensure::run_envs(
            &[
                svccfg,
                "-s",
                "system/svc/restarter:default",
                "addpg",
                "options",
                "application",
            ],
            Some(&env),
        )?;
        ensure::run_envs(
            &[
                svccfg,
                "-s",
                "system/svc/restarter:default",
                "setprop",
                "options/logging=debug",
            ],
            Some(&env),
        )?;
    }

    /*
     * If the image ships a site profile, we may wish to apply it before the
     * first boot.  Otherwise, services that are disabled in the site profile
     * may start up before the profile is applied in the booted system, only to
     * then be disabled again.
     */
    if apply_site {
        let profile_site = format!("{}/var/svc/profile/site.xml", mountpoint);
        ensure::run_envs(&[svccfg, "apply", &profile_site], Some(&env))?;
    }

    ensure::file(&repo, &installto, ROOT, ROOT, 0o600, Create::Always)?;
    ensure::removed(&repo)?;

    Ok(())
}

#[derive(Clone, PartialEq)]
pub struct ShadowFile {
    pub entries: Vec<Vec<String>>,
}

impl ShadowFile {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut f = std::fs::File::open(path.as_ref())?;
        let mut data = String::new();
        f.read_to_string(&mut data)?;

        let entries = data
            .lines()
            .enumerate()
            .map(|(i, l)| {
                let fields = l.split(':').map(str::to_string).collect::<Vec<_>>();
                if fields.len() != 9 {
                    bail!("invalid shadow line {}: {:?}", i, fields);
                }
                Ok(fields)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(ShadowFile { entries })
    }

    pub fn password_set(&mut self, user: &str, password: &str) -> Result<()> {
        /*
         * First, make sure the username appears exactly once in the shadow
         * file.
         */
        let mc = self.entries.iter().filter(|e| e[0] == user).count();
        if mc != 1 {
            bail!("found {} matches for user {} in shadow file", mc, user);
        }

        self.entries.iter_mut().for_each(|e| {
            if e[0] == user {
                e[1] = password.to_string();
            }
        });
        Ok(())
    }

    pub fn write<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path.as_ref())?;

        let mut data = self
            .entries
            .iter()
            .map(|e| e.join(":"))
            .collect::<Vec<_>>()
            .join("\n");
        data.push('\n');

        f.write_all(data.as_bytes())?;
        f.flush()?;
        Ok(())
    }
}

pub enum Fstyp {
    Ufs(Ufs),
    Pcfs(Pcfs),
}

pub enum BuildType {
    Pool(String),
    Dataset,
    Ufs,
    Iso,
    Pcfs,
}

pub struct ImageBuilder {
    pub build_type: BuildType,

    pub group: String,
    pub name: String,
    pub output_name: String,

    pub template_root: PathBuf,
    pub workds: String,
    pub outputds: String,
    pub tmpds: String,
    pub template: Template,
    pub bename: String,

    pub svccfg: String,

    pub features: HashMap<String, String>,
}

impl ImageBuilder {
    /**
     * The root directory of the target system image.  This is the work dataset
     * mountpoint in the case of a dataset build, or the /a directory underneath
     * that for a pool build.
     */
    pub fn root(&self) -> Result<PathBuf> {
        let s = zfs_get(&self.workds, "mountpoint")?;
        let t = zfs_get(&self.tmpds, "mountpoint")?;

        Ok(PathBuf::from(match &self.build_type {
            BuildType::Dataset => s,
            /*
             * When a template targets a pool, files target the mountpoint of
             * the boot environment we create in the pool.
             */
            BuildType::Pool(_) => s + "/a",
            /*
             * When a template targets a UFS or a FAT file system, files target
             * the mountpoint of the file system we create on the lofi device.
             */
            BuildType::Ufs | BuildType::Pcfs => s + "/a",
            /*
             * ISO Files are not created using a lofi device, so we can just
             * use the temporary dataset.
             */
            BuildType::Iso => t + "/proto",
        }))
    }

    pub fn target_pool(&self) -> String {
        if let BuildType::Pool(name) = &self.build_type {
            name.to_string()
        } else {
            panic!("not a pool job");
        }
    }

    /**
     * The name of the pool as it is imported on the build machine.  This name
     * is ephemeral; the target pool name is the "real" name of the pool (e.g.,
     * "rpool") as it will appear on the installed host.
     */
    pub fn temp_pool(&self) -> String {
        if let BuildType::Pool(_) = &self.build_type {
            format!("TEMPORARY-{}-{}", self.group, self.output_name)
        } else {
            panic!("not a pool job");
        }
    }

    pub fn tmpdir(&self) -> Result<PathBuf> {
        let s = zfs_get(&self.tmpds, "mountpoint")?;
        Ok(PathBuf::from(s))
    }

    pub fn tmp_file(&self, n: &str) -> Result<PathBuf> {
        let mut p = PathBuf::from(zfs_get(&self.tmpds, "mountpoint")?);
        p.push(n);
        Ok(p)
    }

    pub fn work_file(&self, n: &str) -> Result<PathBuf> {
        let mut p = PathBuf::from(zfs_get(&self.workds, "mountpoint")?);
        p.push(n);
        Ok(p)
    }

    pub fn output_file(&self, n: &str) -> Result<PathBuf> {
        let mut p = PathBuf::from(zfs_get(&self.outputds, "mountpoint")?);
        p.push(n);
        Ok(p)
    }

    pub fn template_file(&self, filename: &str) -> Result<PathBuf> {
        /*
         * First, try in the group-specific directory:
         */
        let mut s = self.template_root.clone();
        s.push(&format!("{}/files/{}", self.group, filename));
        if let Some(fi) = ensure::check(&s)? {
            if !fi.is_file() {
                bail!(
                    "template file {} is wrong type: {:?}",
                    s.display(),
                    fi.filetype
                );
            }
            return Ok(s);
        }

        /*
         * Otherwise, fall back to the global directory:
         */
        let mut s = self.template_root.clone();
        s.push(&format!("files/{}", filename));
        if let Some(fi) = ensure::check(&s)? {
            if !fi.is_file() {
                bail!(
                    "template file {} is wrong type: {:?}",
                    s.display(),
                    fi.filetype
                );
            }
            return Ok(s);
        }

        bail!("could not find template file \"{}\"", filename);
    }

    pub fn bename(&self) -> &str {
        &self.bename
    }

    pub fn feature_enabled(&self, name: &str) -> bool {
        self.features.contains_key(&name.to_string())
    }

    pub fn expando(&self, value: Option<&str>) -> Result<Option<String>> {
        value.map(|value| self.expand(value)).transpose()
    }

    pub fn expand(&self, value: &str) -> Result<String> {
        Ok(Expansion::parse(value)?.evaluate(&self.features)?)
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct Iso {
    pub boot_bios: Option<String>,
    pub boot_uefi: Option<String>,
    pub volume_id: Option<String>,
    pub hybrid: Option<Hybrid>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Hybrid {
    pub stage1: String,
    pub stage2: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Ufs {
    pub size: usize,
    pub inode_density: usize,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Pcfs {
    pub label: String,
    pub size: usize,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Pool {
    pub name: String,
    pub ashift: Option<u8>,
    pub uefi: Option<bool>,
    pub size: usize,
    pub partition_only: Option<bool>,
}

impl Pool {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn uefi(&self) -> bool {
        /*
         * Default to no EFI System Partition (zpool create -B).
         */
        self.uefi.unwrap_or(false)
    }

    pub fn ashift(&self) -> u8 {
        /*
         * Default to 512 byte sectors.
         */
        self.ashift.unwrap_or(9)
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct Dataset {
    pub name: String,
    pub output_snapshot: Option<String>,
    pub input_snapshot: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Step {
    #[serde(skip, default)]
    pub f: String,
    pub t: String,
    #[serde(default)]
    pub with: Option<String>,
    #[serde(default)]
    pub without: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

pub trait StepExt<T>
where
    for<'de> T: Deserialize<'de>,
{
    fn args(&self) -> Result<T>;
}

impl<T> StepExt<T> for Step
where
    for<'de> T: Deserialize<'de>,
{
    fn args(&self) -> Result<T> {
        Ok(serde_json::from_value(self.extra.clone())?)
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct Template {
    pub dataset: Option<Dataset>,
    pub pool: Option<Pool>,
    pub ufs: Option<Ufs>,
    pub pcfs: Option<Pcfs>,
    pub iso: Option<Iso>,
    pub steps: Vec<Step>,
}

pub fn include_path<P: AsRef<Path>>(root: P, group: &str, name: &str) -> Result<PathBuf> {
    let paths = vec![
        format!("{}/include/{}.json", group, name),
        format!("include/{}.json", name),
    ];

    for p in paths.iter() {
        let mut fp = root.as_ref().to_path_buf();
        fp.push(p);

        if let Some(fi) = ensure::check(&fp)? {
            if fi.is_file() {
                return Ok(fp);
            }
        }
    }

    bail!("could not find include file in: {:?}", paths);
}

pub fn load_template<P>(root: P, group: &str, name: &str, include: bool) -> Result<Template>
where
    P: AsRef<Path>,
{
    let path = if include {
        include_path(root.as_ref(), group, name)?
    } else {
        let mut path = root.as_ref().to_path_buf();
        path.push(format!("{}/{}.json", group, name));
        path
    };
    let f =
        std::fs::File::open(&path).with_context(|| anyhow!("template load path: {:?}", &path))?;
    let mut t: Template = serde_json::from_reader(f)?;
    if include {
        if t.pool.is_some() || t.dataset.is_some() {
            bail!("cannot specify \"pool\" or \"dataset\" in an include");
        }
    } else {
        if t.pool.is_some() && t.dataset.is_some() {
            bail!("cannot specify both \"pool\" and \"dataset\" in a template");
        }
    }

    /*
     * Walk through the steps and expand any "include" entries before we
     * proceed.
     */
    let mut steps: Vec<Step> = Vec::new();
    for mut step in t.steps {
        if step.t == "include" {
            #[derive(Deserialize)]
            struct IncludeArgs {
                name: String,
            }

            let a: IncludeArgs = step.args()?;

            let ti = load_template(root.as_ref(), group, &a.name, true)?;
            for step in ti.steps {
                steps.push(step);
            }
        } else {
            step.f = path.clone().to_string_lossy().to_string();
            steps.push(step);
        }
    }

    t.steps = steps;

    Ok(t)
}
