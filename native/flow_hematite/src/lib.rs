#![feature(cursor_remaining)]
use std::io::{Cursor, Write};

use rustler::{wrapper::binary::new_binary, Binary, OwnedBinary, Term};

#[rustler::nif]
fn add<'a>(env: rustler::Env<'a>, b: Binary<'a>) -> Term<'a> {
    let mut z = Cursor::new(b.as_slice());
    let _block = nbt::Blob::from_reader(&mut z).unwrap();

    let remaining = z.remaining_slice();
    let mut binary = OwnedBinary::new(remaining.len()).unwrap();
    let _ = binary.as_mut_slice().write_all(remaining);
    binary.release(env).to_term(env)

    // a + b
}

rustler::init!("Elixir.Flow.Hematite", [add]);
