// TODO: refactor this function
fn complex(x: i32) -> i32 {
    let mut r = 0;
    if x > 0 { r += 1; }
    if x > 1 { r += 1; }
    if x > 2 { r += 1; }
    if x > 3 { r += 1; }
    if x > 4 { r += 1; }
    if x > 5 { r += 1; }
    if x > 6 { r += 1; }
    if x > 7 { r += 1; }
    if x > 8 { r += 1; }
    if x > 9 { r += 1; }
    if x > 10 { r += 1; }
    if x > 11 { r += 1; }
    if x > 12 { r += 1; }
    if x > 13 { r += 1; }
    if x > 14 { r += 1; }
    if x > 15 { r += 1; }
    let o: Option<i32> = Some(r);
    o.unwrap()
}
