use std::fs;
use std::path::Path;

use super::*;
use crate::descriptor::Layout;
use crate::test_support::{ALL, FIDO_CCID, TestDir, identity};

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{} cannot be read: {error}", path.display()))
}

fn header(identity: &UsbIdentity) -> ConfigHeader {
    Layout::from_identity(identity).expect("layout").config.header
}

#[test]
fn creating_the_gadget_writes_the_device_attributes_strings_configuration_and_function() {
    let dir = TestDir::new();
    let id = identity(FIDO_CCID, Some("12345678"));
    let mut configfs = ConfigFs::new(dir.path(), "lk", "lkf");
    configfs.create(&id, &header(&id)).expect("the tree can be created");
    let gadget = dir.path().join("lk");
    assert_eq!(configfs.gadget_dir(), gadget);
    assert_eq!(read(&gadget.join("idVendor")), "0x1050\n");
    assert_eq!(read(&gadget.join("idProduct")), "0x0406\n");
    assert_eq!(read(&gadget.join("bcdDevice")), "0x0574\n");
    assert_eq!(read(&gadget.join("bcdUSB")), "0x0200\n");
    assert_eq!(read(&gadget.join("max_speed")), "full-speed\n");
    let strings = gadget.join("strings/0x409");
    assert_eq!(read(&strings.join("manufacturer")), "Yubico\n");
    assert_eq!(read(&strings.join("product")), "YubiKey FIDO+CCID\n");
    assert_eq!(read(&strings.join("serialnumber")), "12345678\n");
    let config = gadget.join("configs/c.1");
    assert_eq!(read(&config.join("bmAttributes")), "0x80\n");
    assert_eq!(read(&config.join("MaxPower")), "30\n", "bMaxPower 15 in 2 mA units is 30 mA");
    assert!(!config.join("strings").exists(), "no configuration string: iConfiguration stays 0");
    assert!(gadget.join("functions/ffs.lkf").is_dir());
    assert_eq!(configfs.function_dir(), gadget.join("functions/ffs.lkf"));
    assert!(!gadget.join("UDC").exists(), "binding is not part of creating");
    assert_eq!(configfs.udc_file(), gadget.join("UDC"));
    assert_eq!(
        configfs.created(),
        [
            Created::Dir(gadget.clone()),
            Created::Dir(strings.clone()),
            Created::Dir(gadget.join("functions/ffs.lkf")),
            Created::Dir(config.clone()),
        ]
    );
}

#[test]
fn a_missing_serial_number_is_written_as_the_empty_string() {
    let dir = TestDir::new();
    let id = identity(FIDO_CCID, None);
    let mut configfs = ConfigFs::new(dir.path(), "lk", "lkf");
    configfs.create(&id, &header(&id)).expect("the tree can be created");
    assert_eq!(read(&dir.path().join("lk/strings/0x409/serialnumber")), "\n");
}

#[test]
fn linking_puts_an_absolute_link_to_the_function_into_the_configuration() {
    let dir = TestDir::new();
    let id = identity(FIDO_CCID, None);
    let mut configfs = ConfigFs::new(dir.path(), "lk", "lkf");
    configfs.create(&id, &header(&id)).expect("the tree can be created");
    configfs.link().expect("the link can be created");
    let link = dir.path().join("lk/configs/c.1/ffs.lkf");
    let target = fs::read_link(&link).expect("a symlink");
    assert!(target.is_absolute());
    assert_eq!(target, dir.path().join("lk/functions/ffs.lkf"));
    assert_eq!(configfs.created().last(), Some(&Created::Link(link)));
}

#[test]
fn updating_rewrites_the_product_id_and_strings() {
    let dir = TestDir::new();
    let first = identity(FIDO_CCID, Some("12345678"));
    let mut configfs = ConfigFs::new(dir.path(), "lk", "lkf");
    configfs.create(&first, &header(&first)).expect("the tree can be created");
    let second = UsbIdentity { product: "YubiKey OTP+FIDO+CCID".into(), ..identity(ALL, None) };
    configfs.update(&second).expect("the tree can be updated");
    let gadget = dir.path().join("lk");
    assert_eq!(read(&gadget.join("idProduct")), "0x0407\n");
    assert_eq!(read(&gadget.join("strings/0x409/product")), "YubiKey OTP+FIDO+CCID\n");
    assert_eq!(read(&gadget.join("strings/0x409/serialnumber")), "\n", "the old serial number is cleared");
    assert_eq!(configfs.created().len(), 4, "updating creates nothing");
}

#[test]
fn creating_refuses_an_existing_gadget_directory_and_leaves_it_alone() {
    let dir = TestDir::new();
    fs::create_dir(dir.path().join("lk")).expect("a directory");
    fs::write(dir.path().join("lk/idVendor"), "0xdead\n").expect("a file");
    let id = identity(FIDO_CCID, None);
    let mut configfs = ConfigFs::new(dir.path(), "lk", "lkf");
    let error = configfs.create(&id, &header(&id)).expect_err("the gadget exists");
    assert_eq!(error.path, dir.path().join("lk"));
    assert!(configfs.created().is_empty());
    assert!(configfs.teardown().is_empty());
    assert_eq!(read(&dir.path().join("lk/idVendor")), "0xdead\n");
}

#[test]
fn creating_never_creates_the_root() {
    let dir = TestDir::new();
    let root = dir.path().join("missing");
    let id = identity(FIDO_CCID, None);
    let mut configfs = ConfigFs::new(&root, "lk", "lkf");
    assert!(configfs.create(&id, &header(&id)).is_err());
    assert!(!root.exists());
}

#[test]
fn teardown_removes_the_link_then_the_directories_in_reverse_order_of_creation() {
    let dir = TestDir::new();
    let id = identity(FIDO_CCID, None);
    let mut configfs = ConfigFs::new(dir.path(), "lk", "lkf");
    configfs.create(&id, &header(&id)).expect("the tree can be created");
    configfs.link().expect("the link can be created");
    let gadget = dir.path().join("lk");
    let steps = configfs.teardown();
    let removed: Vec<Created> = steps.iter().map(|step| step.removed.clone()).collect();
    assert_eq!(
        removed,
        [
            Created::Link(gadget.join("configs/c.1/ffs.lkf")),
            Created::Dir(gadget.join("configs/c.1")),
            Created::Dir(gadget.join("functions/ffs.lkf")),
            Created::Dir(gadget.join("strings/0x409")),
            Created::Dir(gadget.clone()),
        ]
    );
    assert!(steps[0].result.is_ok());
    assert!(fs::symlink_metadata(gadget.join("configs/c.1/ffs.lkf")).is_err());
    // The function directory is empty, so it goes; on a plain filesystem the others keep
    // their attribute files (on ConfigFS those belong to the directory and go with it).
    assert!(steps[2].result.is_ok());
    assert!(steps[1].result.is_err() && steps[3].result.is_err() && steps[4].result.is_err());
    assert!(configfs.created().is_empty());
    assert!(configfs.teardown().is_empty(), "a second teardown has nothing left");
}

#[test]
fn the_first_udc_is_the_first_name_in_order() {
    let dir = TestDir::new();
    assert_eq!(first_udc(dir.path()).expect("readable"), None);
    for name in ["musb-hdrc.1", "dummy_udc.1", "dummy_udc.0"] {
        fs::create_dir(dir.path().join(name)).expect("a directory");
    }
    assert_eq!(first_udc(dir.path()).expect("readable"), Some("dummy_udc.0".into()));
    assert!(first_udc(&dir.path().join("missing")).is_err());
}

#[test]
fn errors_name_the_path() {
    let error = ConfigFsError { path: "/x/idVendor".into(), source: io::Error::other("refused") };
    assert_eq!(error.to_string(), "/x/idVendor: refused");
}

#[test]
fn no_gadget_directory_is_no_leftover() {
    let dir = TestDir::new();
    assert!(matches!(ConfigFs::leftover(dir.path(), "lk", "lkf"), Ok(None)));
}

#[test]
fn a_leftover_of_this_transport_is_torn_down_in_the_order_it_was_created_in_reverse() {
    let dir = TestDir::new();
    let id = identity(FIDO_CCID, None);
    let mut configfs = ConfigFs::new(dir.path(), "lk", "lkf");
    configfs.create(&id, &header(&id)).expect("the tree can be created");
    configfs.link().expect("the link can be created");
    // What a killed process leaves: the kernel unbound the gadget when its files closed.
    fs::write(dir.path().join("lk/UDC"), "\n").expect("UDC can be written");
    let leftover = ConfigFs::leftover(dir.path(), "lk", "lkf").expect("ours").expect("a leftover");
    assert_eq!(leftover.created(), configfs.created(), "exactly what create and link made, in their order");
}

#[test]
fn a_partly_created_tree_is_a_leftover_too() {
    let dir = TestDir::new();
    let gadget = dir.path().join("lk");
    fs::create_dir_all(gadget.join("strings/0x409")).expect("a directory");
    fs::create_dir_all(gadget.join("functions")).expect("a directory");
    fs::write(gadget.join("idVendor"), "0x1050\n").expect("an attribute");
    let leftover = ConfigFs::leftover(dir.path(), "lk", "lkf").expect("ours").expect("a leftover");
    assert_eq!(leftover.created(), [Created::Dir(gadget.clone()), Created::Dir(gadget.join("strings/0x409"))]);
}

/// Plants one thing into a gadget directory.
type Plant = fn(&Path);

#[test]
fn a_bound_gadget_or_one_holding_what_this_transport_does_not_make_is_no_leftover() {
    let plant: [(&str, Plant); 9] = [
        ("bound", |g| fs::write(g.join("UDC"), "dummy_udc.0\n").expect("UDC")),
        ("another function", |g| fs::create_dir_all(g.join("functions/hid.usb0")).expect("a directory")),
        ("another configuration", |g| fs::create_dir_all(g.join("configs/c.2")).expect("a directory")),
        ("another language", |g| fs::create_dir_all(g.join("strings/0x407")).expect("a directory")),
        ("a configuration string", |g| fs::create_dir_all(g.join("configs/c.1/strings/0x409")).expect("a directory")),
        ("an os_desc link", |g| {
            fs::create_dir_all(g.join("os_desc")).expect("a directory");
            std::os::unix::fs::symlink(g.join("configs"), g.join("os_desc/c.1")).expect("a link");
        }),
        ("a link to another function", |g| {
            fs::create_dir_all(g.join("configs/c.1")).expect("a directory");
            std::os::unix::fs::symlink(g.join("functions"), g.join("configs/c.1/hid.usb0")).expect("a link");
        }),
        ("a function that is a link", |g| {
            fs::create_dir_all(g.join("functions")).expect("a directory");
            std::os::unix::fs::symlink(g, g.join("functions/ffs.lkf")).expect("a link");
        }),
        ("an unknown group", |g| fs::create_dir_all(g.join("extra")).expect("a directory")),
    ];
    for (what, plant) in plant {
        let dir = TestDir::new();
        let gadget = dir.path().join("lk");
        fs::create_dir(&gadget).expect("a directory");
        plant(&gadget);
        let refused = ConfigFs::leftover(dir.path(), "lk", "lkf").err();
        assert!(refused.is_some(), "{what} is refused");
    }
    let dir = TestDir::new();
    fs::write(dir.path().join("lk"), "").expect("a file");
    assert_eq!(ConfigFs::leftover(dir.path(), "lk", "lkf").err().as_deref(), Some("not a directory"));
    let dir = TestDir::new();
    fs::create_dir(dir.path().join("lk")).expect("a directory");
    fs::write(dir.path().join("lk/UDC"), "dummy_udc.0\n").expect("UDC");
    let reason = ConfigFs::leftover(dir.path(), "lk", "lkf").err().unwrap_or_default();
    assert_eq!(reason, "bound to dummy_udc.0, so in use");
}
