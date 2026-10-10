//! The ConfigFS gadget tree (`docs/PROGRAM.md` "lk-gadget", ConfigFS). Files and
//! directories only, under a root given as a parameter (`/sys/kernel/config/usb_gadget`
//! on a real system, a temporary directory in tests).
//!
//! The procedure is `Documentation/usb/gadget_configfs.rst` ("Creating the gadgets",
//! "Cleaning up"); the attribute formats are those the store functions in
//! `drivers/usb/gadget/configfs.c` accept:
//!
//! - `idVendor`, `idProduct`, `bcdDevice`, `bcdUSB`: `kstrtou16(page, 0, ...)`, so
//!   `0x%04x` is read as hexadecimal; `bcdDevice` and `bcdUSB` must be valid BCD
//!   (`is_valid_bcd`: no digit above 9; the engine's `0x0574` and `0x0200` are).
//!   `bcdUSB` is written because `docs/PROGRAM.md` names it, but it never reaches the
//!   host: `composite_setup` (`drivers/usb/gadget/composite.c`) overwrites it on every
//!   GET_DESCRIPTOR(device) with a value chosen from the controller's capabilities and
//!   the connection speed (see the crate docs, open items).
//! - `max_speed`: prefix match on `full-speed`.
//! - strings: `usb_string_copy` strips one trailing newline, refuses an empty write and
//!   more than `USB_MAX_STRING_LEN` (126) bytes including the newline.
//! - `configs/c.1/MaxPower` is in mA: the composite framework encodes `bMaxPower` as
//!   `MaxPower / 2` below SuperSpeed (`encode_bMaxPower` in
//!   `drivers/usb/gadget/composite.c`), so the engine's `bMaxPower` 15 is written as 30.
//! - `configs/c.1/bmAttributes`: `kstrtou8`; must have bit 7 (`USB_CONFIG_ATT_ONE`) and
//!   no bit other than self-powered and remote wakeup.
//! - `UDC`: one trailing newline is stripped; an empty name unbinds. A zero-byte write
//!   never reaches the store function (configfs passes on only what was written), so
//!   unbinding writes `"\n"`, as `echo "" > UDC` does.
//!
//! Every value is written followed by a newline, as `echo` writes it. Bind and unbind
//! are done by [`crate::GadgetIo`] (so a test kernel can react); [`ConfigFs::udc_file`]
//! names the file.
//!
//! No configuration string is created: the engine's configuration descriptor has
//! `iConfiguration` 0, and the composite framework assigns a string index only to a
//! configuration with a language directory (`configfs_composite_bind`).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use lk_device::UsbIdentity;

use crate::descriptor::ConfigHeader;

/// The configuration directory: label `c`, `bConfigurationValue` 1 (the engine's
/// configuration value; configfs parses the number after the dot).
pub const CONFIG_DIR: &str = "c.1";
/// The gadget strings language directory (US English).
pub const LANGUAGE_DIR: &str = "0x409";
/// The groups ConfigFS creates in every gadget directory (`gadgets_make` in
/// `drivers/usb/gadget/configfs.c`). They cannot be removed on their own and go with the
/// gadget directory.
pub const GADGET_GROUPS: [&str; 5] = ["functions", "configs", "strings", "os_desc", "webusb"];
/// The group ConfigFS creates in every configuration directory (its per-language
/// configuration strings, `drivers/usb/gadget/configfs.c`).
pub const CONFIG_GROUPS: [&str; 1] = ["strings"];

/// A failed ConfigFS operation, with the path.
#[derive(Debug)]
pub struct ConfigFsError {
    pub path: PathBuf,
    pub source: io::Error,
}

impl std::fmt::Display for ConfigFsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.source)
    }
}

impl std::error::Error for ConfigFsError {}

/// Something [`ConfigFs`] created, to be removed in reverse order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Created {
    Dir(PathBuf),
    Link(PathBuf),
}

/// One teardown step and its result.
#[derive(Debug)]
pub struct TeardownStep {
    pub removed: Created,
    pub result: io::Result<()>,
}

/// The gadget's ConfigFS tree:
///
/// ```text
/// <root>/<gadget>/
///   idVendor idProduct bcdDevice bcdUSB max_speed UDC
///   strings/0x409/{manufacturer,product,serialnumber}
///   configs/c.1/{bmAttributes,MaxPower}
///   configs/c.1/ffs.<function> -> <root>/<gadget>/functions/ffs.<function>
///   functions/ffs.<function>/
/// ```
#[derive(Debug)]
pub struct ConfigFs {
    gadget: PathBuf,
    function: String,
    created: Vec<Created>,
}

impl ConfigFs {
    /// The tree for gadget `gadget` and FunctionFS instance `function` under `root`;
    /// nothing is created yet.
    pub fn new(root: &Path, gadget: &str, function: &str) -> ConfigFs {
        ConfigFs { gadget: root.join(gadget), function: format!("ffs.{function}"), created: Vec::new() }
    }

    /// The gadget directory.
    pub fn gadget_dir(&self) -> &Path {
        &self.gadget
    }

    /// The `UDC` attribute.
    pub fn udc_file(&self) -> PathBuf {
        self.gadget.join("UDC")
    }

    /// The function directory `functions/ffs.<function>`.
    pub fn function_dir(&self) -> PathBuf {
        self.gadget.join("functions").join(&self.function)
    }

    /// What was created, in order.
    pub fn created(&self) -> &[Created] {
        &self.created
    }

    /// The tree an earlier process of this transport left at the gadget directory (it was
    /// killed before its teardown), as a `ConfigFs` whose [`ConfigFs::teardown`] removes
    /// it; `Ok(None)` when there is no gadget directory. Reads only.
    ///
    /// When a process that serves the gadget is killed, the kernel closes its FunctionFS
    /// files; with the last one closed f_fs resets the instance and unbinds a gadget that
    /// is still bound (`ffs_data_closed` → `ffs_data_reset` → `ffs_data_clear` →
    /// `ffs_closed` → `unregister_gadget_item`, `drivers/usb/gadget/function/f_fs.c`). The
    /// ConfigFS tree and the FunctionFS mount stay. A leftover is therefore recognised
    /// by:
    ///
    /// - its `UDC` reading as an empty line (`gadget_dev_desc_UDC_show` prints the bound
    ///   controller's name, or nothing), or missing (then it is no real ConfigFS gadget
    ///   and nothing can be bound). A bound gadget is in use and refused;
    /// - holding no directory and no symbolic link this transport does not create: in the
    ///   gadget directory only [`GADGET_GROUPS`]; in `functions` only `ffs.<function>`; in
    ///   `configs` only `c.1`; in `configs/c.1` only [`CONFIG_GROUPS`] and the link
    ///   `ffs.<function>`; in `strings` only `0x409`; nothing in `configs/c.1/strings`,
    ///   `strings/0x409`, `os_desc` and `webusb`. Regular files are attributes and are not
    ///   looked at; the inside of the function directory belongs to f_fs. A tree that was
    ///   only partly created (a kill during [`ConfigFs::create`]) qualifies too.
    ///
    /// Anything else is someone else's gadget and is refused with the reason. A live
    /// process of this transport with the same names whose gadget is unbound at the
    /// moment cannot be told from a leftover; two daemons must not share a gadget name.
    pub fn leftover(root: &Path, gadget: &str, function: &str) -> Result<Option<ConfigFs>, String> {
        let mut tree = ConfigFs::new(root, gadget, function);
        let gadget_dir = tree.gadget.clone();
        match fs::symlink_metadata(&gadget_dir) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.to_string()),
            Ok(meta) if !meta.is_dir() => return Err("not a directory".into()),
            Ok(_) => {}
        }
        match fs::read_to_string(tree.udc_file()) {
            Ok(udc) if udc.trim().is_empty() => {}
            Ok(udc) => return Err(format!("bound to {}, so in use", udc.trim())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("UDC: {error}")),
        }
        let function_name = tree.function.clone();
        let config_dir = gadget_dir.join("configs").join(CONFIG_DIR);
        let strings_dir = gadget_dir.join("strings").join(LANGUAGE_DIR);
        let link = config_dir.join(&function_name);
        let function_dir = tree.function_dir();
        holds_only(&gadget_dir, &GADGET_GROUPS, &[])?;
        holds_only(&gadget_dir.join("functions"), &[&function_name], &[])?;
        holds_only(&gadget_dir.join("configs"), &[CONFIG_DIR], &[])?;
        holds_only(&config_dir, &CONFIG_GROUPS, &[&function_name])?;
        holds_only(&gadget_dir.join("strings"), &[LANGUAGE_DIR], &[])?;
        let (os_desc, webusb) = (gadget_dir.join("os_desc"), gadget_dir.join("webusb"));
        for dir in [config_dir.join("strings"), strings_dir.clone(), os_desc, webusb] {
            holds_only(&dir, &[], &[])?;
        }
        // In the order `create` and `link` make them, so that teardown reverses it.
        tree.created.push(Created::Dir(gadget_dir));
        for dir in [strings_dir, function_dir, config_dir] {
            if dir.is_dir() {
                tree.created.push(Created::Dir(dir));
            }
        }
        if fs::symlink_metadata(&link).is_ok_and(|meta| meta.file_type().is_symlink()) {
            tree.created.push(Created::Link(link));
        }
        Ok(Some(tree))
    }

    /// Create the gadget directory (it must not exist), write the device attributes and
    /// strings, create the FunctionFS function directory (it must exist before `mount -t
    /// functionfs <function>`, which looks the instance up by name), and create
    /// `configs/c.1` with `bmAttributes` and `MaxPower` from `config`. The function comes
    /// before the configuration so that the reverse order of creation is also the
    /// cleanup order of `gadget_configfs.rst` (configurations before functions). On an
    /// error, [`ConfigFs::teardown`] removes what was created.
    pub fn create(&mut self, identity: &UsbIdentity, config: &ConfigHeader) -> Result<(), ConfigFsError> {
        let gadget = self.gadget.clone();
        self.make_dir(&gadget)?;
        self.write_device(identity)?;
        write_attr(&gadget.join("max_speed"), "full-speed")?;
        self.make_dir(&gadget.join("strings").join(LANGUAGE_DIR))?;
        self.write_strings(identity)?;
        let function_dir = self.function_dir();
        self.make_dir(&function_dir)?;
        let config_dir = gadget.join("configs").join(CONFIG_DIR);
        self.make_dir(&config_dir)?;
        write_attr(&config_dir.join("bmAttributes"), &format!("0x{:02x}", config.attributes))?;
        write_attr(&config_dir.join("MaxPower"), &(u16::from(config.max_power) * 2).to_string())?;
        Ok(())
    }

    /// Link the function into `configs/c.1`. The target is absolute: configfs resolves
    /// a symlink's target when it is created, relative to the creating process's working
    /// directory (`configfs_symlink` → `get_target` → `kern_path`).
    pub fn link(&mut self) -> Result<(), ConfigFsError> {
        let link = self.gadget.join("configs").join(CONFIG_DIR).join(&self.function);
        std::os::unix::fs::symlink(self.function_dir(), &link)
            .map_err(|source| ConfigFsError { path: link.clone(), source })?;
        self.created.push(Created::Link(link));
        Ok(())
    }

    /// Rewrite the device attributes and strings for a new identity (re-enumeration,
    /// while unbound).
    pub fn update(&mut self, identity: &UsbIdentity) -> Result<(), ConfigFsError> {
        self.write_device(identity)?;
        self.write_strings(identity)
    }

    /// Remove what was created, in reverse order: the link, then `configs/c.1`,
    /// `functions/ffs.<function>`, `strings/0x409` and the gadget directory (the order of
    /// `gadget_configfs.rst` "Cleaning up"). Every step is attempted; the results say
    /// which failed. Unbinding and unmounting come first and are the caller's.
    pub fn teardown(&mut self) -> Vec<TeardownStep> {
        let mut steps = Vec::new();
        while let Some(created) = self.created.pop() {
            let result = match &created {
                Created::Link(path) => fs::remove_file(path),
                Created::Dir(path) => fs::remove_dir(path),
            };
            steps.push(TeardownStep { removed: created, result });
        }
        steps
    }

    /// `idVendor`, `idProduct`, `bcdDevice`, `bcdUSB` from the device descriptor (`bcdUSB`
    /// is replaced by `composite.c` before the host sees it; see the module docs).
    fn write_device(&self, identity: &UsbIdentity) -> Result<(), ConfigFsError> {
        let device = identity.device_descriptor();
        let bcd_usb = u16::from_le_bytes([device[2], device[3]]);
        for (name, value) in [
            ("idVendor", identity.vendor_id),
            ("idProduct", identity.product_id),
            ("bcdDevice", identity.device_release),
            ("bcdUSB", bcd_usb),
        ] {
            write_attr(&self.gadget.join(name), &format!("0x{value:04x}"))?;
        }
        Ok(())
    }

    /// `strings/0x409/{manufacturer,product,serialnumber}`. Without a serial number the
    /// attribute is set to the empty string (a lone newline: an empty write is refused),
    /// so a serial number of an earlier enumeration is not shown again. The host still
    /// gets string index 3 with an empty string, not the engine's `iSerialNumber` 0: the
    /// composite framework indexes every gadget string slot (`copy_gadget_strings` turns
    /// an unset one into "" too; see the crate docs, open items).
    fn write_strings(&self, identity: &UsbIdentity) -> Result<(), ConfigFsError> {
        let dir = self.gadget.join("strings").join(LANGUAGE_DIR);
        write_attr(&dir.join("manufacturer"), &identity.manufacturer)?;
        write_attr(&dir.join("product"), &identity.product)?;
        write_attr(&dir.join("serialnumber"), identity.serial.as_deref().unwrap_or(""))
    }

    /// Create one directory and remember it. Its parent must exist on a real ConfigFS
    /// (the gadget's `configs`, `functions` and `strings` are default groups); elsewhere
    /// (a test directory) missing parents inside the gadget directory are created and not
    /// remembered. The root itself is never created.
    fn make_dir(&mut self, path: &Path) -> Result<(), ConfigFsError> {
        if path != self.gadget
            && let Some(parent) = path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent).map_err(|source| ConfigFsError { path: parent.to_owned(), source })?;
        }
        fs::create_dir(path).map_err(|source| ConfigFsError { path: path.to_owned(), source })?;
        self.created.push(Created::Dir(path.to_owned()));
        Ok(())
    }
}

/// Refuse a directory in `dir` not named in `dirs`, a symbolic link not named in `links`,
/// and anything else that is neither a regular file nor a directory; regular files are
/// attributes. A missing `dir` holds nothing.
fn holds_only(dir: &Path, dirs: &[&str], links: &[&str]) -> Result<(), String> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", dir.display())),
    };
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
        let kind = entry.file_type().map_err(|error| format!("{}: {error}", entry.path().display()))?;
        let name = entry.file_name();
        let named = |names: &[&str]| name.to_str().is_some_and(|name| names.contains(&name));
        let ours = if kind.is_dir() {
            named(dirs)
        } else if kind.is_symlink() {
            named(links)
        } else {
            kind.is_file()
        };
        if !ours {
            return Err(format!("{} is not made by this transport", entry.path().display()));
        }
    }
    Ok(())
}

/// Write one attribute as `echo` does: the value and a newline, in one write.
fn write_attr(path: &Path, value: &str) -> Result<(), ConfigFsError> {
    fs::write(path, format!("{value}\n")).map_err(|source| ConfigFsError { path: path.to_owned(), source })
}

/// The first USB device controller listed in `class_dir` (`/sys/class/udc` on a real
/// system; `gadget_configfs.rst`: "the list of available UDCs is in /sys/class/udc/"),
/// by name order. `None` if there is none.
pub fn first_udc(class_dir: &Path) -> io::Result<Option<String>> {
    let mut names: Vec<String> = fs::read_dir(class_dir)?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();
    Ok(names.into_iter().next())
}

#[cfg(test)]
mod tests;
