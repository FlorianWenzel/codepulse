// TODO: replace the unsafe block
fn process(data: Option<i32>, ptr: *mut i32) {
    let v = data.unwrap();
    unsafe {
        *ptr = v;
    }
    if v < 0 {
        panic!("negative");
    }
}
