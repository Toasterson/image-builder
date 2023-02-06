use anyhow::{anyhow, Context, bail, Result};
use log::*;
use std::collections::HashMap;
use uuid::Uuid;
use std::process::exit;
use slog::{Drain, Logger};
use slog_async::Async;
use slog_scope::{set_global_logger, GlobalLoggerGuard};
use slog_syslog::Facility;
use slog_term::{CompactFormat, TermDecorator};
use slog_scope::crit;
use illumos_image_builder::*;
use illumos_image_builder::expand::Expansion;
use illumos_image_builder::ROOT;
use illumos_image_builder::ensure::{Create, HashType};
use serde::{Deserialize};
use std::path::PathBuf;

fn init_slog_logging(use_syslog: bool) -> Result<GlobalLoggerGuard> {
    if use_syslog {
        let drain = slog_syslog::unix_3164(Facility::LOG_DAEMON)?.fuse();
        let logger = Logger::root(drain, slog::slog_o!());

        let scope_guard = set_global_logger(logger);
        let _log_guard = slog_stdlog::init()?;

        Ok(scope_guard)
    } else {
        let decorator = TermDecorator::new().stdout().build();
        let drain = CompactFormat::new(decorator).build().fuse();
        let drain = Async::new(drain).build().fuse();
        let logger = Logger::root(drain, slog::slog_o!());

        let scope_guard = set_global_logger(logger);
        let _log_guard = slog_stdlog::init()?;

        Ok(scope_guard)
    }
}

fn main() -> Result<()> {
    let _guard = init_slog_logging(false)?;

    let cmd = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("missing command name"))?;

    let mut opts = getopts::Options::new();
    opts.parsing_style(getopts::ParsingStyle::StopAtFirstFree);

    fn usage(opts: &getopts::Options) {
        let s = opts.usage("image-builder");
        println!("{}", s);
    }

    let f = match cmd.as_str() {
        "build" => {
            opts.optflag("r", "reset", "destroy any work-in-progress dataset");
            opts.optflag("x", "fullreset", "destroy dataset");
            opts.reqopt("g", "group", "group name", "GROUPNAME");
            opts.reqopt("n", "name", "image name", "IMAGENAME");
            opts.optopt("N", "output-name", "output image name", "IMAGENAME");
            opts.reqopt("d", "dataset", "root dataset for work", "DATASET");
            opts.optopt("T", "templates", "directory for templates", "DIR");
            opts.optopt("S", "svccfg", "svccfg-native location", "SVCCFG");
            opts.optmulti(
                "F",
                "feature",
                "add or remove a feature definition",
                "[^]FEATURE[=VALUE]",
            );

            run_build
        }
        n => {
            usage(&opts);
            bail!("invalid command: {}", n);
        }
    };

    let mat = match opts.parse(std::env::args().skip(2)) {
        Ok(mat) => mat,
        Err(e) => {
            usage(&opts);
            bail!("invalid options: {:?}", e);
        }
    };

    if let Err(e) = f(&mat) {
        crit!("fatal error: {:?}", e);
        exit(1);
    }

    Ok(())
}

fn run_build(mat: &getopts::Matches) -> Result<()> {
    let group = mat.opt_str("g").unwrap();
    let name = mat.opt_str("n").unwrap();
    let output_name = if let Some(n) = mat.opt_str("N") {
        /*
         * Allow the user to override the name we use for the work area and
         * output files, as distinct from the template name.
         */
        n
    } else {
        name.clone()
    };
    let ibrootds = mat.opt_str("d").unwrap();
    let fullreset = mat.opt_present("x");
    let reset = mat.opt_present("r");
    let template_root = find_template_root(mat.opt_str("T"))?;

    /*
     * Process feature directives in the order in which they appear.  Directives
     * can override the value of previous definitions, and can remove a feature
     * already defined, to hopefully easily enable argument lists to be
     * constructed in control programs that override default values.
     *
     */
    let mut feature_directives = mat
        .opt_strs("F")
        .iter()
        .map(|o| {
            let o = o.trim();

            Ok(if o.is_empty() {
                bail!("-f requires an argument");
            } else if o.starts_with('^') {
                /*
                 * This is a negated feature; i.e., -F ^BLAH
                 */
                if o.contains('=') {
                    bail!("-f with a negated feature cannot have a value");
                }
                (o.chars().skip(1).collect::<String>(), None)
            } else if let Some((f, v)) = o.split_once('=') {
                /*
                 * This is an enabled feature with a value; i.e., -F BLAH=YES
                 */
                (f.trim().to_string(), Some(v.to_string()))
            } else {
                /*
                 * This is an enabled feature with no value; i.e., -F BLAH
                 * Just set it to "1", as if the user had passed: -F BLAH=1
                 */
                (o.to_string(), Some("1".to_string()))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut features = HashMap::new();
    for (f, v) in feature_directives.drain(..) {
        if let Some(v) = v {
            features.insert(f, v);
        } else {
            features.remove(&f);
        }
    }

    /*
     * Using the system svccfg(1M) is acceptable under some conditions, but not
     * all.  This is only safe as long as the service bundle DTD, and the
     * service bundles in the constructed image, as well as the target
     * repository database file format, are compatible with the build system
     * svccfg.  Sadly it is also not generally correct to use the svccfg program
     * from the image under construction, as it may depend on newer libc or
     * kernel or other private interfaces than are available on the build
     * system.
     *
     * If a new feature is required, then the "svccfg-native" binary from the
     * built illumos tree will be required.  Indeed, for a completely robust
     * image build process, that program should always be used.
     */
    let svccfg = mat
        .opt_str("S")
        .unwrap_or_else(|| "/usr/sbin/svccfg".to_string());

    let t = load_template(&template_root, &group, &name, false)
        .context(format!("loading template {}:{}", group, name))?;

    if !dataset_exists(&ibrootds)? {
        bail!("image builder root dataset \"{}\" does not exist", ibrootds);
    }

    /*
     * Create a dataset to hold the output files of various builds.
     */
    let outputds = format!("{}/output", ibrootds);
    if !dataset_exists(&outputds)? {
        dataset_create(&outputds, false)?;
    }

    let tmpds = format!("{}/tmp/{}/{}", ibrootds, group, output_name);
    info!("temporary dataset: {}", tmpds);
    if dataset_exists(&tmpds)? {
        dataset_remove(&tmpds)?;
    }
    dataset_create(&tmpds, true)?;
    zfs_set(&tmpds, "sync", "disabled")?;
    let tmpdir = zfs_get(&tmpds, "mountpoint")?;
    info!("temporary directory: {}", tmpdir);

    /*
     * XXX Generate a unique bename.  This is presently necessary because beadm
     * does not accept an altroot (-R) flag, and thus the namespace for boot
     * environments overlaps between "real" boot environments in use on the host
     * and any we create on the target image while it is mounted.
     *
     * Ideally, this will go away with changes to illumos.
     */
    let bename = Uuid::new_v4().as_hyphenated().to_string()[0..8].to_string();

    let c = t.ufs.is_some() as u32
        + t.pcfs.is_some() as u32
        + t.iso.is_some() as u32
        + t.pool.is_some() as u32
        + t.dataset.is_some() as u32;
    if c > 1 {
        bail!(
            "template must have at most one of \"dataset\", \"ufs\", \
            \"pool\", or \"iso\""
        );
    }

    if t.dataset.is_none() {
        let workds = format!("{}/work/{}/{}", ibrootds, group, output_name);
        info!("work dataset: {}", workds);

        if !dataset_exists(&workds)? {
            /*
             * For pool jobs, we just create the target dataset.  The temporary
             * pool will be destroyed and created as a lofi image inside this
             * dataset, providing the required idempotency.
             */
            dataset_create(&workds, true)?;
        }

        /*
         * We can disable sync on the work dataset to make writes to the lofi
         * device go a lot faster.  If the system crashes, we're going to start
         * this build again anyway.  Output files are stored in a different
         * dataset where sync is not disabled.  It would be tempting to put the
         * image in the temporary dataset rather than the work dataset, but we
         * destroy that unconditionally for each run and if we left a lingering
         * lofi device open that was attached in the temporary dataset that
         * would fail.
         */
        zfs_set(&workds, "sync", "disabled")?;

        let (build_type, func) = if let Some(pool) = &t.pool {
            (
                BuildType::Pool(pool.name().to_string()),
                run_build_pool as Build,
            )
        } else if t.ufs.is_some() {
            (BuildType::Ufs, run_build_fs as Build)
        } else if t.pcfs.is_some() {
            (BuildType::Pcfs, run_build_fs as Build)
        } else if t.iso.is_some() {
            (BuildType::Iso, run_build_iso as Build)
        } else {
            panic!("expected one or the other");
        };

        let mut ib = ImageBuilder {
            build_type,
            bename,
            group,
            name,
            output_name,
            template_root,
            template: t,
            workds,
            outputds,
            tmpds,
            svccfg,
            features,
        };

        (func)(&mut ib)?;

        /*
         * Work datasets for builds that result in image files can be safely
         * removed after a successful build as they are not re-used in
         * subsequent builds.  A failure to remove the dataset at this stage
         * would imply we did not clean up all of the lofi devices, etc.
         */
        dataset_remove(&ib.workds)?;
        dataset_remove(&ib.tmpds)?;

        return Ok(());
    }

    let dataset = t.dataset.as_ref().unwrap();
    let dataset_name = Expansion::parse(&dataset.name)?.evaluate(&features)?;

    let workds = format!("{}/work/{}/{}", ibrootds, group, dataset_name);
    info!("work dataset: {}", workds);

    let mut ib = ImageBuilder {
        build_type: BuildType::Dataset,
        bename,
        group: group.clone(),
        name: name.clone(),
        output_name,
        template_root,
        template: t.clone(),
        workds: workds.clone(),
        outputds,
        tmpds,
        svccfg,
        features,
    };

    let input_snapshot = ib.expando(dataset.input_snapshot.as_deref())?;
    let output_snapshot = ib.expando(dataset.output_snapshot.as_deref())?;

    if fullreset {
        info!("resetting by removing work dataset: {}", workds);
        dataset_remove(&workds)?;
    }

    if dataset_exists(&workds)? {
        /*
         * The dataset exists already.  If this template has configured an
         * output snapshot, we can roll back to it without doing any more work.
         */
        if let Some(snap) = output_snapshot.as_deref() {
            info!("looking for output snapshot {}@{}", workds, snap);
            if snapshot_exists(&workds, snap)? && !reset {
                snapshot_rollback(&workds, snap)?;
                info!(
                    "rolled back to output snapshot; \
                    no work required"
                );
                return Ok(());
            }

            if input_snapshot.is_none() {
                /*
                 * If there is no input snapshot, we do not know how to make
                 * the dataset pristine for this build.  Bail out.
                 */
                bail!(
                    "the dataset exists, but an input snapshot was not \
                    specified and the output snapshot does not exist; \
                    a full reset is required"
                );
            }
        }

        /*
         * If an input snapshot was specified, then we know how to reset the
         * dataset to a pristine state at which this build may begin.
         */
        if let Some(snap) = input_snapshot.as_deref() {
            info!("looking for input snapshot {}@{}", workds, snap);
            if snapshot_exists(&workds, snap)? {
                snapshot_rollback(&workds, snap)?;
                info!("rolled back to input snapshot; work may begin");
            } else {
                bail!(
                    "the dataset exists, but the specified input snapshot \
                    does not; a full reset is required"
                );
            }
        } else {
            assert!(output_snapshot.is_none());
            assert!(input_snapshot.is_none());

            bail!(
                "the dataset exists, but neither an input nor an output \
                snapshot was specified; a full reset is required"
            );
        }

        assert!(input_snapshot.is_some());
    }

    dataset_create(&workds, true)?;

    run_steps(&mut ib)?;

    if let Some(snap) = output_snapshot.as_deref() {
        info!("creating output snapshot {}@{}", workds, snap);
        snapshot_create(&workds, snap)?;
    }

    /*
     * Remove the temporary dataset we created for this build.  Note that we do
     * not remove the work dataset, as multiple file-tree builds will act on
     * that dataset in sequence.
     */
    dataset_remove(&ib.tmpds)?;

    info!("completed processing {}/{}", group, name);

    Ok(())
}

fn run_build_fs(ib: &mut ImageBuilder) -> Result<()> {
    let fstyp = if let Some(ufs) = ib.template.ufs.as_ref() {
        Fstyp::Ufs(ufs.clone())
    } else if let Some(pcfs) = ib.template.pcfs.as_ref() {
        Fstyp::Pcfs(pcfs.clone())
    } else {
        bail!("expected a \"ufs\" or \"pcfs\" property");
    };

    /*
     * Arrange this structure:
     *  /ROOT_DATASET/group/name
     *      /lofi.$fsname -- the lofi image underpinning the UFS/FAT image
     *      /a -- UFS/FAT root mountpoint
     *
     * Steps like "ensure_file" will have their root directory relative to "/a".
     * This directory represents "/" (the root file system) in the target boot
     * environment.
     */

    /*
     * First, ensure there is no file system mounted at our expected location:
     */
    let rmp = ib.root()?;

    loop {
        let mounts = illumos::mounts()?
            .iter()
            .filter(|m| rmp == PathBuf::from(&m.mount_point))
            .cloned()
            .collect::<Vec<_>>();
        if mounts.is_empty() {
            break;
        }
        info!("found old mounts: {:#?}", mounts);
        ensure::run(&["/sbin/umount", "-f", rmp.to_str().unwrap()])?;
    }
    info!("nothing mounted at {:?}", rmp);

    let (fsname, size) = match &fstyp {
        Fstyp::Ufs(ufs) => ("ufs", ufs.size),
        Fstyp::Pcfs(pcfs) => ("pcfs", pcfs.size),
    };

    /*
     * Now, make sure we have a fresh lofi device...
     */
    let imagefile = ib.work_file(&format!("lofi.{}", fsname))?;
    info!("image file: {}", imagefile.display());

    /*
     * Create a regular (unlabelled) lofi(7D) device.  We do not need to
     * manipulate slices to create the ramdisk image:
     */
    let lofi = recreate_lofi(&imagefile, size, false)?;
    let ldev = lofi.devpath.unwrap();
    let lrdev = lofi.rdevpath.unwrap();

    let mntopts = match &fstyp {
        Fstyp::Ufs(ufs) => {
            ensure::run(&[
                "/usr/sbin/newfs",
                "-o",
                "space",
                "-m",
                "0",
                "-i",
                &ufs.inode_density.to_string(),
                "-b",
                "4096",
                ldev.to_str().unwrap(),
            ])?;
            "nologging,noatime"
        }
        Fstyp::Pcfs(pcfs) => {
            /*
             * Because we are using the "nofdisk" option, we need to specify the
             * target file system size in term of 512 byte sectors:
             */
            let secsize = size * 1024 * 1024 / 512;
            ensure::run(&[
                "/usr/sbin/mkfs",
                "-F",
                "pcfs",
                "-o",
                &format!("b={},nofdisk,size={}", pcfs.label, secsize),
                lrdev.to_str().unwrap(),
            ])?;
            "noatime"
        }
    };

    ensure::directory(&rmp, ROOT, ROOT, 0o755)?;

    ensure::run(&[
        "/usr/sbin/mount",
        "-F",
        fsname,
        "-o",
        mntopts,
        ldev.to_str().unwrap(),
        rmp.to_str().unwrap(),
    ])?;

    /*
     * Now that we have created the file system, run the steps for this
     * template.
     */
    run_steps(ib)?;

    info!("steps complete; finalising image!");

    /*
     * Report the used and available space in the temporary pool before we
     * export it.
     */
    if let Fstyp::Ufs(_) = &fstyp {
        /*
         * Only UFS has inodes.
         */
        ensure::run(&["/usr/bin/df", "-o", "i", rmp.to_str().unwrap()])?;
    }
    ensure::run(&["/usr/bin/df", "-h", rmp.to_str().unwrap()])?;

    /*
     * Unmount the file system and detach the lofi device.
     */
    ensure::run(&["/sbin/umount", rmp.to_str().unwrap()])?;
    lofi::lofi_unmap_device(&ldev)?;

    /*
     * Copy the image file to the output directory.
     */
    let outputfile = ib.output_file(&format!("{}-{}.{}", ib.group, ib.output_name, fsname))?;

    info!(
        "copying image {} to output file {}",
        imagefile.display(),
        outputfile.display()
    );
    ensure::removed(&outputfile)?;
    std::fs::copy(&imagefile, &outputfile)?;
    ensure::perms(&outputfile, ROOT, ROOT, 0o644)?;

    info!("completed processing {}/{}", ib.group, ib.name);

    Ok(())
}

fn run_build_pool(ib: &mut ImageBuilder) -> Result<()> {
    let temppool = ib.temp_pool();

    /*
     * Arrange this structure:
     *  /ROOT_DATASET/group/name
     *      /lofi.raw -- the lofi image underpinning the pool
     *      /altroot -- pool altroot (zpool create -R)
     *      /a -- boot environment mount directory?
     *
     * Steps like "ensure_file" will have their root directory relative to "/a".
     * This directory represents "/" (the root file system) in the target boot
     * environment.
     *
     * The temporary pool name will be "TEMPORARY-$group-$name".
     */

    /*
     * First, destroy a pool if we have left one around...
     */
    pool_destroy(&temppool)?;

    /*
     * Now, make sure we have a fresh lofi device...
     */
    let imagefile = ib.work_file("lofi.raw")?;
    info!("image file: {}", imagefile.display());

    let altroot = ib.work_file("altroot")?;
    info!("pool altroot: {}", altroot.display());

    let pool = ib.template.pool.as_ref().unwrap();

    /*
     * Attach this file as a labelled lofi(7D) device so that we can manage
     * slices.
     */
    let lofi = recreate_lofi(&imagefile, pool.size(), true)?;
    let ldev = lofi.devpath.as_ref().unwrap();

    let disk = ldev.to_str().unwrap().trim_end_matches("p0");
    info!("pool device = {}", disk);

    /*
     * Create the new pool, using the temporary pool name while it is imported
     * on this system.  We specify an altroot to avoid using the system cache
     * file, and to avoid mountpoint clashes with the system pool.  If we do not
     * explicitly set the mountpoint of the pool (create -m ...) then it will
     * default to the dynamically constructed "/$poolname", which will be
     * correct both on this system and on the target system when it is
     * eventually imported as its target name.
     */
    let mut args = vec![
        "/sbin/zpool",
        "create",
        "-d",
        "-t",
        &temppool,
        "-O",
        "compression=on",
        "-R",
        altroot.to_str().unwrap(),
    ];

    if pool.uefi() {
        /*
         * If we need UEFI support, we must pass -B to create the
         * ESP slice.  Note that this consumes 256MB of space in the
         * image.
         */
        args.push("-B");
    }

    args.push("-o");
    let ashiftarg = format!("ashift={}", pool.ashift());
    args.push(&ashiftarg);

    let targpool = ib.target_pool();
    args.push(&targpool);
    args.push(disk);

    ensure::run(args.as_slice())?;

    /*
     * Now that we have created the pool, run the steps for this template.
     */
    run_steps(ib)?;

    info!("steps complete; finalising image!");

    /*
     * Report the used and available space in the temporary pool before we
     * export it.
     */
    info!(
        "temporary pool has {} used, {} avail, {} compressratio",
        zfs_get(&temppool, "used")?,
        zfs_get(&temppool, "avail")?,
        zfs_get(&temppool, "compressratio")?
    );

    /*
     * Export the pool and detach the lofi device.
     */
    pool_export(&temppool)?;

    if ib
        .template
        .pool
        .as_ref()
        .unwrap()
        .partition_only
        .unwrap_or(false)
    {
        let outpartfile = ib.output_file(&format!("{}-{}.partonly", ib.group, ib.output_name))?;
        ensure::removed(&outpartfile)?;
        info!("extract just the ZFS partition to {:?}", outpartfile);

        let uefi = ib.template.pool.as_ref().unwrap().uefi.unwrap_or(false);
        let slice = if uefi { "1" } else { "0" };

        ensure::run(&[
            "dd",
            &format!("if={}s{}", disk.replace("dsk", "rdsk"), slice),
            &format!("of={}", outpartfile.to_str().unwrap()),
            "bs=256k",
        ])?;
    }

    lofi::lofi_unmap_device(&ldev)?;

    /*
     * Copy the image file to the output directory.
     */
    let outputfile = ib.output_file(&format!("{}-{}.raw", ib.group, ib.output_name))?;

    info!(
        "copying image {} to output file {}",
        imagefile.display(),
        outputfile.display()
    );
    ensure::removed(&outputfile)?;
    std::fs::copy(&imagefile, &outputfile)?;
    ensure::perms(&outputfile, ROOT, ROOT, 0o644)?;

    info!("completed processing {}/{}", ib.group, ib.name);

    Ok(())
}

fn run_build_iso(ib: &mut ImageBuilder) -> Result<()> {
    /*
     * Steps like "ensure_file" will have their root directory relative to
     * "/proto" in the temporary dataset.  This directory represents the root of
     * the target ISO image.
     */
    let rmp = ib.root()?;
    assert!(!rmp.exists());
    ensure::directory(&rmp, ROOT, ROOT, 0o755)?;

    /*
     * Now that we have created the proto directory, run the steps for this
     * template.
     */
    run_steps(ib)?;

    info!("steps complete; finalising image!");

    let iso = ib.template.iso.as_ref().unwrap();

    if iso.hybrid.is_some() && iso.boot_uefi.is_none() {
        /*
         * XXX Due to limitations in installboot(1M), it is not presently
         * possible to specify a device path for boot loader installation unless
         * there is a numbered partition (not the whole disk) on which an
         * identifiable file system is present.  Without the ESP image embedded
         * in the ISO, we have no such file system to specify.
         */
        bail!("presently all hybrid images must include UEFI support");
    }

    let imagefile = ib.work_file("output.iso")?;
    teardown_lofi(&imagefile)?;
    ensure::removed(&imagefile)?;

    let mut args = vec![
        "/usr/bin/mkisofs",
        "-N",
        "-l",
        "-R",
        "-U",
        "-d",
        "-D",
        "-c",
        ".catalog",
        "-allow-multidot",
        "-no-iso-translate",
        "-cache-inodes",
    ];
    if let Some(volume_id) = iso.volume_id.as_deref() {
        args.push("-V");
        args.push(volume_id);
    }
    let mut need_alt = false;
    if let Some(boot_bios) = iso.boot_bios.as_deref() {
        args.push("-eltorito-boot");
        args.push(boot_bios);
        args.push("-no-emul-boot");
        args.push("-boot-info-table");
        need_alt = true;
    }
    if let Some(boot_uefi) = iso.boot_uefi.as_deref() {
        if need_alt {
            args.push("-eltorito-alt-boot");
        }
        args.push("-eltorito-platform");
        args.push("efi");
        args.push("-eltorito-boot");
        args.push(boot_uefi);
        args.push("-no-emul-boot");
    }
    args.push("-o");
    args.push(imagefile.to_str().unwrap());
    args.push(rmp.to_str().unwrap());
    ensure::run(&args)?;

    /*
     * If this is to be a hybrid ISO (i.e., can also be used as a USB boot disk)
     * we need to create a partition table that maps to the appropriate regions
     * of the ISO image.
     */
    if let Some(hybrid) = iso.hybrid.as_ref() {
        if iso.boot_uefi.is_none() {
            bail!("hybrid images must support UEFI at present");
        }

        /*
         * Attach the ISO image file as a labelled lofi device, so that we can
         * use fdisk(1M) and installboot(1M):
         */
        let lofi = attach_lofi(&imagefile, true)?;
        let rdev = lofi.rdevpath.as_ref().unwrap();

        /*
         * Create a small x86 boot partition (type 190) near the start of the
         * ISO, from sector 3 up to sector 63.  The installboot(1M) utility will
         * place the stage2 loader file (which can boot from the ISO portion of
         * the image) there.
         *
         * The ISO data itself begins at sector 64.
         */
        fdisk_add(rdev, 190, 3, 60)?;

        if iso.boot_uefi.is_some() {
            /*
             * Locate the EFI system partition image within the ISO file:
             */
            let esp = etdump(&imagefile, "efi", "i386")?;
            info!("esp @ {:?}", esp);

            /*
             * Create a partition table entry so that EFI firmware knows to
             * look for the ESP:
             */
            let start = (esp.offset as u32) / 512;
            let nsectors = (esp.length as u32) / 512;
            fdisk_add(rdev, 239, start, nsectors)?;
        }

        /*
         * The p0 device represents the whole disk.  Unfortunately, installboot
         * does not presently accept such a path; it requires the path to a file
         * system for which it can identify the type.  We choose the ESP, which
         * is the second partition in our MBR table.
         */
        let p0 = rdev.to_str().unwrap();
        let p2 = if let Some(rdsk) = p0.strip_suffix("p0") {
            format!("{}p2", rdsk)
        } else {
            bail!("unexpected lofi device path: {}", p0);
        };

        let stage1 = format!("{}/{}", rmp.to_str().unwrap(), hybrid.stage1);
        let stage2 = format!("{}/{}", rmp.to_str().unwrap(), hybrid.stage2);
        installboot(&p2, &stage1, &stage2)?;

        teardown_lofi(&imagefile)?;
    }

    /*
     * Copy the image file to the output directory.
     */
    let outputfile = ib.output_file(&format!("{}-{}.iso", ib.group, ib.output_name))?;

    info!(
        "copying image {} to output file {}",
        imagefile.display(),
        outputfile.display()
    );
    ensure::removed(&outputfile)?;
    std::fs::copy(&imagefile, &outputfile)?;
    ensure::perms(&outputfile, ROOT, ROOT, 0o644)?;

    info!("completed processing {}/{}", ib.group, ib.name);

    Ok(())
}

pub fn run_steps(ib: &mut ImageBuilder) -> Result<()> {
    for (count, step) in ib.template.steps.iter().enumerate() {
        info!(target: &step.f, "STEP {}: {}", count, step.t);

        /*
         * If this step is dependent on being with or without a particular
         * feature, check for the present of that feature:
         */
        if let Some(feature) = step.with.as_deref() {
            if !ib.feature_enabled(feature) {
                info!("skip step because feature {:?} is not enabled", feature);
                continue;
            }
        }
        if let Some(feature) = step.without.as_deref() {
            if ib.feature_enabled(feature) {
                info!("skip step because feature {:?} is enabled", feature);
                continue;
            }
        }

        match step.t.as_str() {
            "create_be" => {
                /*
                 * Create root pool:
                 */
                let rootds = format!("{}/ROOT", ib.temp_pool());
                dataset_create(&rootds, false)?;
                zfs_set(&rootds, "canmount", "off")?;
                zfs_set(&rootds, "mountpoint", "legacy")?;

                /*
                 * Create a BE of sorts:
                 */
                let beds = format!("{}/{}", rootds, ib.bename());
                dataset_create(&beds, false)?;
                zfs_set(&beds, "canmount", "noauto")?;
                zfs_set(&beds, "mountpoint", "legacy")?;

                /*
                 * Mount that BE:
                 */
                let targmp = ib.root()?;
                ensure::directory(&targmp, ROOT, ROOT, 0o755)?;
                ensure::run(&["/sbin/mount", "-F", "zfs", &beds, targmp.to_str().unwrap()])?;

                /*
                 * Set some BE properties...
                 */
                let uuid = Uuid::new_v4().as_hyphenated().to_string();
                info!("boot environment UUID: {}", uuid);
                zfs_set(&beds, "org.opensolaris.libbe:uuid", &uuid)?;
                zfs_set(&beds, "org.opensolaris.libbe:policy", "static")?;
            }
            "create_dataset" => {
                #[derive(Deserialize)]
                struct CreateDatasetArgs {
                    name: String,
                    mountpoint: Option<String>,
                }

                let a: CreateDatasetArgs = step.args()?;
                let ds = format!("{}/{}", ib.temp_pool(), a.name);
                dataset_create(&ds, false)?;
                if let Some(mp) = &a.mountpoint {
                    zfs_set(&ds, "mountpoint", mp)?;
                }
            }
            "remove_files" => {
                #[derive(Deserialize)]
                struct RemoveFilesArgs {
                    file: Option<PathBuf>,
                    dir: Option<PathBuf>,
                    pattern: Option<String>,
                }

                let a: RemoveFilesArgs = step.args()?;

                match (&a.file, &a.dir, &a.pattern) {
                    (Some(f), None, None) => {
                        if !f.is_absolute() {
                            bail!("file should be an absolute path");
                        }

                        let mut actual = ib.root()?;
                        actual.extend(f.components().skip(1));
                        info!("remove file: {:?}", actual);
                        std::fs::remove_file(actual)?;
                    }
                    (None, Some(d), None) => {
                        if !d.is_absolute() {
                            bail!("dir should be an absolute path");
                        }

                        let mut actual = ib.root()?;
                        actual.extend(d.components().skip(1));
                        info!("remove tree: {:?}", actual);
                        std::fs::remove_dir_all(actual)?;
                    }
                    (None, None, Some(p)) => {
                        let g = glob::Pattern::new(p)?;
                        let mut w = walkdir::WalkDir::new(ib.root()?)
                            .min_depth(1)
                            .follow_links(false)
                            .contents_first(true)
                            .same_file_system(true)
                            .into_iter();
                        while let Some(ent) = w.next().transpose()? {
                            if !ent.file_type().is_file() {
                                continue;
                            }

                            if let Some(s) = ent.file_name().to_str() {
                                if g.matches(s) {
                                    info!("remove file: {:?}", ent.path());
                                    std::fs::remove_file(ent.path())?;
                                }
                                continue;
                            } else {
                                bail!("path {:?} cannot be matched?", ent.path());
                            }
                        }
                    }
                    _ => {
                        bail!(
                            "must specify exactly one of \"file\", \"dir\", \
                            or \"pattern\""
                        );
                    }
                }
            }
            "unpack_tar" => {
                #[derive(Deserialize)]
                struct UnpackTarArgs {
                    name: String,
                    into_tmp: Option<bool>,
                }

                let a: UnpackTarArgs = step.args()?;
                let name = ib.expand(&a.name)?;
                let targdir = if a.into_tmp.unwrap_or(false) {
                    /*
                     * Store unpacked files in a temporary directory so that
                     * "ensure_file" steps can access the unpacked files using
                     * the "tarsrc" source.
                     */
                    let dir = ib.tmp_file("unpack_tar")?;
                    if dir.exists() {
                        std::fs::remove_dir_all(&dir)?;
                    }
                    std::fs::create_dir(&dir)?;
                    dir.to_str().unwrap().to_string()
                } else {
                    let mp = ib.root()?;
                    mp.to_str().unwrap().to_string()
                };

                /*
                 * Unpack a tar file of an image created by another build:
                 */
                let tarf = ib.output_file(&name)?;
                ensure::run(&[
                    "/usr/sbin/tar",
                    "xzeEp@/f",
                    tarf.to_str().unwrap(),
                    "-C",
                    &targdir,
                ])?;
            }
            "pack_tar" => {
                #[derive(Deserialize)]
                struct PackTarArgs {
                    name: String,
                    include: Option<Vec<String>>,
                }

                let a: PackTarArgs = step.args()?;
                let name = ib.expand(&a.name)?;
                let mp = ib.root()?;

                /*
                 * Create a tar file of the contents of the IPS image that we
                 * can subsequently unpack into ZFS pools or UFS file systems.
                 */
                let tarf = ib.output_file(&name)?;
                ensure::removed(&tarf)?;

                let mut args = vec!["/usr/sbin/tar", "czeEp@/f", tarf.to_str().unwrap()];
                if let Some(include) = &a.include {
                    include.iter().for_each(|s| {
                        args.push("-C");
                        args.push(mp.to_str().unwrap());
                        args.push(s.as_str());
                    });
                } else {
                    args.push("-C");
                    args.push(mp.to_str().unwrap());
                    args.push(".");
                }
                ensure::run(&args)?;
            }
            "onu" => {
                #[derive(Deserialize)]
                struct OnuArgs {
                    repo: String,
                    publisher: String,
                    #[serde(default)]
                    uninstall: Vec<String>,
                }

                let a: OnuArgs = step.args()?;
                let repo = ib.expand(&a.repo)?;
                let publisher = ib.expand(&a.publisher)?;
                let mp = ib.root()?;
                let targmp = mp.to_str().unwrap();

                /*
                 * Upgrade to onu bits:
                 */
                let publ = "on-nightly";
                pkg(&[
                    "-R",
                    targmp,
                    "set-publisher",
                    "--no-refresh",
                    "--non-sticky",
                    &publisher,
                ])?;
                pkg(&[
                    "-R",
                    targmp,
                    "set-publisher",
                    "-e",
                    "--no-refresh",
                    "-P",
                    "-O",
                    &repo,
                    publ,
                ])?;
                pkg(&["-R", targmp, "refresh", "--full"])?;
                if !a.uninstall.is_empty() {
                    let mut args = vec!["-R", targmp, "uninstall"];
                    for pkg in a.uninstall.iter() {
                        args.push(pkg.as_str());
                    }
                    pkg(&args)?;
                }
                pkg(&["-R", targmp, "change-facet", "onu.ooceonly=false"])?;
                pkg(&["-R", targmp, "update"])?;
                pkg(&["-R", targmp, "purge-history"])?;
            }
            "devfsadm" => {
                let mp = ib.root()?;
                let targmp = mp.to_str().unwrap();

                /*
                 * Create expected /dev structure.  Note that this can leak some
                 * amount of device information from the live system into the
                 * image; templates should clean up any unexpected links or
                 * nodes.
                 */
                ensure::run(&["/usr/sbin/devfsadm", "-r", targmp])?;
            }
            "assemble_files" => {
                let mp = ib.root()?;
                let targmp = mp.to_str().unwrap();

                /*
                 * This step mimics assemble_files() in the OmniOS bootadm.
                 */
                #[derive(Deserialize)]
                struct AssembleFileArgs {
                    dir: String,
                    output: String,
                    prefix: Option<String>,
                }

                let a: AssembleFileArgs = step.args()?;

                if !a.dir.starts_with('/') || !a.output.starts_with('/') {
                    bail!("dir and output must be fully qualified");
                }

                let indir = format!("{}{}", targmp, a.dir);
                let outfile = format!("{}{}", targmp, a.output);

                let mut files: Vec<String> = Vec::new();
                let mut diri = std::fs::read_dir(&indir)?;
                while let Some(ent) = diri.next().transpose()? {
                    if !ent.file_type().unwrap().is_file() {
                        continue;
                    }

                    let n = ent.file_name();
                    let n = n.to_str().unwrap();
                    if let Some(prefix) = a.prefix.as_deref() {
                        if !n.starts_with(prefix) {
                            continue;
                        }
                    }

                    files.push(ent.path().to_str().unwrap().to_string());
                }

                files.sort();

                let mut outstr = String::new();
                for f in files.iter() {
                    let inf = std::fs::read_to_string(&f)?;
                    let out = inf.trim();
                    if out.is_empty() {
                        continue;
                    }
                    outstr += out;
                    if !outstr.ends_with('\n') {
                        outstr += "\n";
                    }
                }

                ensure::filestr(&outstr, &outfile, ROOT, ROOT, 0o644, Create::Always)?;
            }
            "shadow" => {
                #[derive(Deserialize)]
                struct ShadowArgs {
                    username: String,
                    password: Option<String>,
                }

                let a: ShadowArgs = step.args()?;

                /*
                 * Read the shadow file:
                 */
                let mut path = ib.root()?;
                path.push("etc");
                path.push("shadow");

                let orig = ShadowFile::load(&path)?;
                let mut copy = orig.clone();

                if let Some(password) = a.password.as_deref() {
                    copy.password_set(&a.username, password)?;
                }

                if orig == copy {
                    info!("no change to shadow file; skipping write");
                } else {
                    info!("updating shadow file");
                    copy.write(&path)?;
                    ensure::perms(&path, ROOT, ROOT, 0o400)?;
                }
            }
            "gzip" => {
                let mp = ib.root()?;
                let targmp = mp.to_str().unwrap();

                #[derive(Deserialize)]
                struct DigestArgs {
                    target: String,
                    src: String,
                    owner: String,
                    group: String,
                    mode: String,
                }

                let a: DigestArgs = step.args()?;
                let owner = translate_uid(&a.owner)?;
                let group = translate_gid(&a.group)?;

                if !a.target.starts_with('/') {
                    bail!("target must be fully qualified path");
                }
                let target = format!("{}{}", targmp, a.target);

                let mode = u32::from_str_radix(&a.mode, 8)?;

                if a.src.starts_with('/') {
                    bail!("source file must be a relative path");
                }
                let src = ib.output_file(&a.src)?;

                gzip(&src, &target)?;
                ensure::perms(&target, owner, group, mode)?;
            }
            "digest" => {
                let mp = ib.root()?;
                let targmp = mp.to_str().unwrap();

                #[derive(Deserialize)]
                struct DigestArgs {
                    algorithm: String,
                    target: String,
                    src: String,
                    owner: String,
                    group: String,
                    mode: String,
                }

                let a: DigestArgs = step.args()?;
                let owner = translate_uid(&a.owner)?;
                let group = translate_gid(&a.group)?;

                let ht = match a.algorithm.as_str() {
                    "sha1" => HashType::SHA1,
                    "md5" => HashType::MD5,
                    x => bail!("unknown digest algorithm {}", x),
                };

                if !a.target.starts_with('/') {
                    bail!("target must be fully qualified path");
                }
                let target = format!("{}{}", targmp, a.target);

                let mode = u32::from_str_radix(&a.mode, 8)?;

                if a.src.starts_with('/') {
                    bail!("source file must be a relative path");
                }
                let src = ib.output_file(&a.src)?;

                let mut hash = ensure::hash_file(&src, &ht)?;
                hash += "\n";

                ensure::filestr(&hash, &target, owner, group, mode, Create::Always)?;
            }
            "ensure_symlink" => {
                let mp = ib.root()?;
                let targmp = mp.to_str().unwrap();

                #[derive(Deserialize)]
                struct SymlinkArgs {
                    link: String,
                    target: String,
                    owner: String,
                    group: String,
                }

                let a: SymlinkArgs = step.args()?;
                let owner = translate_uid(&a.owner)?;
                let group = translate_gid(&a.group)?;

                if !a.link.starts_with('/') {
                    bail!("link must be fully qualified path");
                }
                let link = format!("{}{}", targmp, a.link);

                ensure::symlink(&link, &a.target, owner, group)?;
            }
            "ensure_perms" => {
                let mp = ib.root()?;
                let targmp = mp.to_str().unwrap();

                #[derive(Deserialize)]
                struct PermsArgs {
                    path: String,
                    owner: String,
                    group: String,
                    mode: String,
                }

                let a: PermsArgs = step.args()?;
                let owner = translate_uid(&a.owner)?;
                let group = translate_gid(&a.group)?;

                if !a.path.starts_with('/') {
                    bail!("path must be fully qualified path");
                }
                let path = format!("{}{}", targmp, a.path);

                let mode = u32::from_str_radix(&a.mode, 8)?;

                ensure::perms(&path, owner, group, mode)?;
            }
            "ensure_directory" | "ensure_dir" => {
                let mp = ib.root()?;
                let targmp = mp.to_str().unwrap();

                #[derive(Deserialize)]
                struct DirArgs {
                    dir: String,
                    owner: String,
                    group: String,
                    mode: String,
                }

                let a: DirArgs = step.args()?;
                let owner = translate_uid(&a.owner)?;
                let group = translate_gid(&a.group)?;

                if !a.dir.starts_with('/') {
                    bail!("dir must be fully qualified path");
                }
                let dir = format!("{}{}", targmp, a.dir);

                let mode = u32::from_str_radix(&a.mode, 8)?;

                ensure::directory(&dir, owner, group, mode)?;
            }
            "ensure_file" => {
                let mp = ib.root()?;
                let targmp = mp.to_str().unwrap();

                #[derive(Deserialize)]
                struct FileArgs {
                    src: Option<String>,
                    imagesrc: Option<String>,
                    tarsrc: Option<String>,
                    outputsrc: Option<String>,
                    contents: Option<String>,
                    file: String,
                    owner: String,
                    group: String,
                    mode: String,
                }

                let a: FileArgs = step.args()?;
                let owner = translate_uid(&a.owner)?;
                let group = translate_gid(&a.group)?;

                if !a.file.starts_with('/') {
                    bail!("file must be fully qualified path");
                }
                let file = format!("{}{}", targmp, a.file);

                let mode = u32::from_str_radix(&a.mode, 8)?;

                if let Some(src) = &a.src {
                    /*
                     * "src" specifies a source file from within the template
                     * directory structure, whether at the top level or at the
                     * group-specific level.
                     */
                    if src.starts_with('/') {
                        bail!("source file must be a relative path");
                    }
                    let src = ib.template_file(src)?;
                    ensure::file(&src, &file, owner, group, mode, Create::Always)?;
                } else if let Some(outputsrc) = &a.outputsrc {
                    /*
                     * "outputsrc" specifies a source file from within the
                     * output area.  Useful for including the output of a
                     * previous build (e.g., an EFI system partition) as a file
                     * in the target image (e.g., a bootable ISO).
                     */
                    if outputsrc.starts_with('/') {
                        bail!("output source file must be a relative path");
                    }
                    let src = ib.output_file(outputsrc)?;
                    ensure::file(&src, &file, owner, group, mode, Create::Always)?;
                } else if let Some(imagesrc) = &a.imagesrc {
                    /*
                     * "imagesrc" specifies a source file that already exists
                     * within the image.  Can be used to make a copy of an
                     * existing file at another location.
                     */
                    if !imagesrc.starts_with('/') {
                        bail!("image source file must be fully qualified");
                    }
                    let src = format!("{}{}", targmp, imagesrc);
                    ensure::file(&src, &file, owner, group, mode, Create::Always)?;
                } else if let Some(tarsrc) = &a.tarsrc {
                    /*
                     * "tarsrc" specifies a file in the temporary directory
                     * created by the last "unpack_tar" action that used
                     * "into_tmp".  This can be used to unpack a tar file and
                     * then copy select files from inside that archive to new
                     * names and paths within the target image.
                     */
                    if !tarsrc.starts_with('/') {
                        bail!("tmp tar source file must be fully qualified");
                    }
                    let tardir = ib.tmp_file("unpack_tar")?;
                    let src = format!("{}{}", tardir.to_str().unwrap(), tarsrc);
                    ensure::file(&src, &file, owner, group, mode, Create::Always)?;
                } else if let Some(contents) = &a.contents {
                    /*
                     * "contents" provides a literal string in the template to
                     * construct the target file.
                     */
                    ensure::filestr(contents, &file, owner, group, mode, Create::Always)?;
                } else {
                    bail!("must specify either \"src\" or \"contents\"");
                }
            }
            "make_bootable" => {
                let mp = ib.root()?;
                let targmp = mp.to_str().unwrap();

                let rootds = format!("{}/ROOT", ib.temp_pool());
                let beds = format!("{}/{}", rootds, ib.bename());
                zpool_set(&ib.temp_pool(), "bootfs", &beds)?;

                ensure::run(&["/sbin/beadm", "activate", ib.bename()])?;
                ensure::run(&[
                    "/sbin/bootadm",
                    "install-bootloader",
                    "-M",
                    "-f",
                    "-P",
                    &ib.temp_pool(),
                    "-R",
                    targmp,
                ])?;
                ensure::run(&["/sbin/bootadm", "update-archive", "-f", "-R", targmp])?;
            }
            "pkg_image_create" => {
                #[derive(Deserialize)]
                struct PkgImageCreateArgs {
                    publisher: String,
                    uri: String,
                }

                let a: PkgImageCreateArgs = step.args()?;
                let mp = ib.root()?;
                pkg(&[
                    "image-create",
                    "--full",
                    "--publisher",
                    &format!("{}={}", a.publisher, a.uri),
                    mp.to_str().unwrap(),
                ])?;
            }
            "pkg_install" => {
                #[derive(Deserialize)]
                struct PkgInstallArgs {
                    pkgs: Vec<String>,
                    #[serde(default)]
                    include_optional: bool,
                    strip_optional_publishers: Option<bool>,
                }

                let a: PkgInstallArgs = step.args()?;
                let mp = ib.root()?;

                let pkgs: Vec<_> = a.pkgs.iter().map(|s| s.as_str()).collect();
                pkg_install(mp.to_str().unwrap(), pkgs.as_slice())?;

                if a.include_optional {
                    let mut pkgs = Vec::new();

                    /*
                     * By default it seems that IPS ignores the publisher in an
                     * FMRI for a require dependency, and we should also.
                     */
                    let strip_publishers = a.strip_optional_publishers.unwrap_or(true);

                    /*
                     * For each package, expand any optional dependencies and
                     * add those to the install list.
                     *
                     * XXX It's possible we should look at the
                     * "opensolaris.zone" variant here; for now we assume we are
                     * in the global zone and all packages are OK.
                     */
                    for pkg in a.pkgs.iter() {
                        let opts = pkg_optional_deps(
                            mp.to_str().unwrap(),
                            pkg.as_str(),
                            strip_publishers,
                        )?;

                        for opt in opts {
                            if pkgs.contains(&opt) {
                                continue;
                            }

                            info!("optional package: {} -> {}", pkg, opt);
                            pkgs.push(opt);
                        }
                    }

                    if !pkgs.is_empty() {
                        let pkgs: Vec<_> = pkgs.iter().map(|s| s.as_str()).collect();
                        pkg_install(mp.to_str().unwrap(), pkgs.as_slice())?;
                    }
                }
            }
            "pkg_set_property" => {
                #[derive(Deserialize)]
                struct PkgSetPropertyArgs {
                    name: String,
                    value: String,
                }

                let a: PkgSetPropertyArgs = step.args()?;
                let mp = ib.root()?;

                pkg(&[
                    "-R",
                    mp.to_str().unwrap(),
                    "set-property",
                    &a.name,
                    &a.value,
                ])?;
            }
            "pkg_set_publisher" => {
                #[derive(Deserialize)]
                struct PkgSetPublisherArgs {
                    publisher: String,
                    uri: String,
                }

                let a: PkgSetPublisherArgs = step.args()?;
                let mp = ib.root()?;

                pkg(&[
                    "-R",
                    mp.to_str().unwrap(),
                    "set-publisher",
                    "--no-refresh",
                    "-O",
                    &a.uri,
                    &a.publisher,
                ])?;
            }
            "pkg_approve_ca_cert" => {
                #[derive(Deserialize)]
                struct PkgApproveCaCertArgs {
                    publisher: String,
                    certfile: String,
                }

                let a: PkgApproveCaCertArgs = step.args()?;
                let mp = ib.root()?;

                /*
                 * The certificate file to use is in the templates area.
                 */
                if a.certfile.starts_with('/') {
                    bail!("certificate file must be a relative path");
                }
                let cacert = ib.template_file(&a.certfile)?.to_str().unwrap().to_string();

                pkg(&[
                    "-R",
                    mp.to_str().unwrap(),
                    "set-publisher",
                    &format!("--approve-ca-cert={}", &cacert),
                    &a.publisher,
                ])?;
            }
            "pkg_uninstall" => {
                #[derive(Deserialize)]
                struct PkgUninstallArgs {
                    pkgs: Vec<String>,
                }

                let a: PkgUninstallArgs = step.args()?;
                let mp = ib.root()?;
                let pkgs: Vec<_> = a.pkgs.iter().map(|s| s.as_str()).collect();
                pkg_uninstall(mp.to_str().unwrap(), pkgs.as_slice())?;
            }
            "pkg_change_variant" => {
                #[derive(Deserialize)]
                struct PkgChangeVariantArgs {
                    variant: String,
                    value: String,
                }

                let a: PkgChangeVariantArgs = step.args()?;
                let mp = ib.root()?;
                pkg_ensure_variant(mp.to_str().unwrap(), &a.variant, &a.value)?;
            }
            "pkg_change_facet" => {
                #[derive(Deserialize)]
                struct PkgChangeFacetArgs {
                    facet: String,
                    value: String,
                }

                let a: PkgChangeFacetArgs = step.args()?;
                let mp = ib.root()?;
                pkg_ensure_facet(mp.to_str().unwrap(), &a.facet, &a.value)?;
            }
            "pkg_purge_history" => {
                let mp = ib.root()?;
                pkg(&["-R", mp.to_str().unwrap(), "purge-history"])?;
            }
            "seed_smf" => {
                #[derive(Deserialize)]
                struct SeedSmfArgs {
                    debug: Option<bool>,
                    apply_site: Option<bool>,
                }

                let a: SeedSmfArgs = step.args()?;
                let debug = a.debug.unwrap_or(false);
                let apply_site = a.apply_site.unwrap_or(false);

                seed_smf(&ib.svccfg, &ib.tmpdir()?, &ib.root()?, debug, apply_site)?;
            }
            x => {
                bail!("INVALID STEP TYPE: {}", x);
            }
        }

        info!("STEP {} ({}) COMPLETE\n", count, step.t);
    }

    Ok(())
}
