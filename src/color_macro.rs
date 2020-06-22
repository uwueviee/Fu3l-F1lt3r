#[macro_export]
macro_rules! regular_out {
    ($input:expr) => {
        println!("{} {}", "[*]".color("blue"), $input);
    }
}

#[macro_export]
macro_rules! okay_out {
    ($input:expr) => {
        println!("{} {}", "[*]".green(), $input);
    }
}

#[macro_export]
macro_rules! warning_out {
    ($input:expr) => {
        println!("{} {}", "[*]".yellow(), $input);
    }
}

#[macro_export]
macro_rules! error_out {
    ($input:expr) => {
        println!("{} {}", "[*]".red(), $input);
    }
}