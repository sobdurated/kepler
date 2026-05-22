// entry point, logic is in lib.rs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    kepler_lib::run()
}
