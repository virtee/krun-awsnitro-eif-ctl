// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use build::*;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cmd {
    #[command(subcommand)]
    pub subcmd: Subcmd,
}

#[derive(Subcommand)]
enum Subcmd {
    Build(BuildArgs),
}

fn main() -> Result<()> {
    let cmd = Cmd::parse();

    let status = match cmd.subcmd {
        Subcmd::Build(args) => build::build(args),
    };

    if let Err(ref e) = status {
        eprintln!("ERROR: {e}");
        e.chain()
            .skip(1)
            .for_each(|cause| eprintln!("\tcause: {cause}"));
    }

    status
}

/// Subcommand to build a new EIF image.
pub mod build {
    use super::*;
    use anyhow::Context;
    use aws_nitro_enclaves_image_format::{
        defs::{EIF_HDR_ARCH_ARM64, EifBuildInfo, EifIdentityInfo},
        utils::EifBuilder,
    };
    use chrono::{DateTime, Utc};
    use clap::ValueEnum;
    use cpio::{NewcBuilder, newc::trailer};
    use serde_json::Value;
    use sha2::{Digest, Sha384};
    use std::{
        fs::{self, File, OpenOptions},
        io,
        path::{Path, PathBuf},
        time::SystemTime,
    };

    #[derive(Clone, Debug, ValueEnum)]
    pub enum Arch {
        #[clap(name = "x86_64")]
        X86_64,
        #[clap(name = "aarch64")]
        Aarch64,
    }

    struct Initrd {
        path: PathBuf,
        init: PathBuf,
        modules: Vec<PathBuf>,
    }

    impl TryFrom<&BuildArgs> for Initrd {
        type Error = anyhow::Error;

        fn try_from(args: &BuildArgs) -> Result<Self> {
            let modules: Vec<PathBuf> = {
                let json_str = fs::read_to_string(&args.kernel_modules).context(format!(
                    "unable to read {:?} to string",
                    args.kernel_modules
                ))?;

                serde_json::from_str(&json_str).context(format!(
                    "unable to deserialize {:?} to JSON array",
                    args.kernel_modules
                ))?
            };

            Ok(Self {
                path: args.initrd.clone(),
                init: args.init.clone(),
                modules,
            })
        }
    }

    impl Initrd {
        fn build(&mut self) -> Result<()> {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(self.path.clone())
                .context(format!("unable to create/open {:?}", self.path))?;

            self.write_file("init", &self.init.clone(), &mut file)?;

            let mods_dir = NewcBuilder::new("krun_linux_mods")
                .mode(0o40755)
                .set_mode_file_type(cpio::newc::ModeFileType::Directory);
            let writer = mods_dir.write(&mut file, 0);
            writer.finish().context(
                "unable to create directory to store configurable enclave kernel modules",
            )?;

            for entry in self.modules.iter() {
                let file_osstr = entry.file_name().context(format!(
                    "unable to get OS file name of {:?}",
                    entry.as_path()
                ))?;
                let file_name = file_osstr.to_str().context(format!(
                    "unable to get file name string of {:?}",
                    entry.as_path()
                ))?;

                self.write_file(&format!("krun_linux_mods/{}", file_name), entry, &mut file)?;
            }

            let _ = trailer(&file).context("unable to write trailer entry to CPIO archive")?;

            Ok(())
        }

        fn write_file(&self, name: &str, path: &Path, file: &mut File) -> Result<()> {
            let cpio = NewcBuilder::new(name)
                .mode(0o100755)
                .dev_major(3)
                .dev_minor(1);

            let contents = fs::read(path).context(format!("unable to read from {:?}", path))?;

            let mut writer = cpio.write(
                file,
                contents
                    .len()
                    .try_into()
                    .context(format!("unable to convert file size of {:?} to u32", path))?,
            );
            io::copy(&mut contents.as_slice(), &mut writer).context(format!(
                "unable to copy contents of {:?} to CPIO archive writer",
                path
            ))?;

            writer.finish().context(format!(
                "unable to complete write of {:?} to CPIO archive",
                path
            ))?;

            Ok(())
        }
    }

    /// Arguments to configure the EIF file built for use in krun-awsnitro.
    #[derive(Parser)]
    pub(super) struct BuildArgs {
        /// Architecture the EIF is being built for.
        #[arg(long)]
        arch: Arch,
        /// Enclave kernel.
        #[arg(short, long)]
        kernel: PathBuf,
        /// Enclave kernel cmdline.
        #[arg(short, long, default_value = "/etc/krun-awsnitro/cmdline")]
        cmdline: PathBuf,
        /// krun-awsnitro init binary.
        #[arg(long, default_value = "/etc/krun-awsnitro/init")]
        init: PathBuf,
        /// JSON-serialized kernel modules to include in the enclave image.
        #[arg(long)]
        kernel_modules: PathBuf,
        /// Path to write the krun-awsnitro initrd.
        #[arg(long, default_value = "/etc/krun-awsnitro/bootstrap-initrd.img")]
        initrd: PathBuf,
        /// Path to write the EIF image to.
        #[arg(short, long, default_value = "/etc/krun-awsnitro/krun-awsnitro.eif")]
        path: PathBuf,
        /// Show PCR measurements
        #[arg(long, default_value = "false")]
        show_measurements: bool,
    }

    pub(super) fn build(args: BuildArgs) -> Result<()> {
        let build_info = build_info(&args)?;

        let cmdline = fs::read_to_string(&args.cmdline)
            .with_context(|| format!("unable to read cmdline from {}", args.cmdline.display()))?;

        let flags = match args.arch {
            Arch::X86_64 => 0,
            Arch::Aarch64 => EIF_HDR_ARCH_ARM64,
        };

        let mut initrd = Initrd::try_from(&args).context("unable to build initrd")?;
        initrd.build().context("unable to build initrd")?;

        let mut build = EifBuilder::new(
            &args.kernel,
            cmdline,
            None,
            Sha384::new(),
            flags,
            build_info,
        );

        build.add_ramdisk(Path::new(&args.initrd));

        let mut output = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(args.path)
            .context("failed to create output file")?;

        let measurements = build.write_to(&mut output);
        if args.show_measurements {
            println!("{:#?}", measurements);
        }

        Ok(())
    }

    fn build_info(args: &BuildArgs) -> Result<EifIdentityInfo> {
        let kernel_name = args
            .kernel
            .file_name()
            .context("unable to get kernel name for EIF build info")?
            .to_str()
            .context("invalid kernel name for EIF build info")?;

        let datetime: DateTime<Utc> = SystemTime::now().into();
        let version = env!("CARGO_PKG_VERSION").to_string();

        Ok(EifIdentityInfo {
            img_name: "krun-awsnitro-eif".to_string(),
            img_version: "n/a".to_string(),
            build_info: EifBuildInfo {
                build_time: format!("{}", datetime),
                build_tool: "krun-awsnitro-eif-ctl".to_string(),
                build_tool_version: version,
                img_os: "n/a".to_string(),
                img_kernel: kernel_name.to_string(),
            },
            docker_info: Value::Null,
            custom_info: Value::Null,
        })
    }
}
