use std::fs;
use std::num::IntErrorKind;
use std::path::Path;
use std::path::PathBuf;
use xxhash_rust::xxh3::xxh3_64;
use std::fs::File;
use std::io::{Read, Write};
use std::io;
use walkdir::WalkDir;
use std::io::{BufReader, BufWriter};
use rayon::prelude::*;
use std::sync::Arc;
use rayon::ThreadPoolBuilder;
use num_cpus;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{Instant, Duration};
use std::thread;




pub enum CopyReason  {
    NewFile,
    Modified,
    SizeDiffers,
}

pub struct FileAction {
    source_path: PathBuf,    
    dest_path: PathBuf,
    size: u64,
    reason: CopyReason,
}


fn file_checksum(path: &PathBuf) -> std::io::Result<u64> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(xxh3_64(&buffer))
}

fn dir_size(path: &Path) -> u64 {
    WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

fn count_files(path: &Path) -> u64 {
    WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count() as u64
}



fn compare_directories(source: &Path, dest: &Path, checksum: bool, measure_size: u8) -> Result<Vec<FileAction>, std::io::Error> {

    let start = Instant::now();
    let mut total_count = match measure_size{
        1 => count_files(source),
        2 => dir_size(source),
        _ => 1
    };
    println!("Zeit: {:.2?}", start.elapsed());



    let start = Instant::now();

    let mut file_actions: Vec<FileAction> = Vec::new();
    file_actions.reserve(10000);

    let mut to_visit = vec![source.to_path_buf()];

    let mut scanned_bytes : u64 = 0; let mut count:u64 = 0;

    while let Some(current) = to_visit.pop() {
        for entry in fs::read_dir(&current)? {
            let entry = entry?;
            let src_path = entry.path();

            if src_path.is_dir() {
                to_visit.push(src_path);
            } else {
                let relative = src_path.strip_prefix(source).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                let dest_path = Path::new(dest).to_path_buf().join(relative);
                let meta_src = fs::metadata(&src_path)?;

                if dest_path.exists() {
                    let meta_dest = fs::metadata(&dest_path)?;
                    
                    if meta_dest.len() != meta_src.len() {
                        let fa = FileAction {source_path:src_path, dest_path: dest_path, size: meta_src.len(), reason: CopyReason::SizeDiffers,};
                        file_actions.push(fa);

                    }
                    else if meta_dest.modified().ok() != meta_src.modified().ok() {
                        let fa = FileAction {source_path:src_path, dest_path: dest_path, size: meta_src.len(), reason: CopyReason::Modified,};
                        file_actions.push(fa);

                    }
                    else if checksum && file_checksum(&src_path)? != file_checksum(&dest_path)? {
                        let fa = FileAction {source_path:src_path, dest_path: dest_path, size: meta_src.len(), reason: CopyReason::Modified,};
                        file_actions.push(fa);
                    }
                    
                }
                else {
                  
                    let fa = FileAction {source_path:src_path, dest_path: dest_path.clone(), size: meta_src.len(), reason: CopyReason::NewFile,};
                    file_actions.push(fa);
                }

                scanned_bytes += meta_src.len();
                count +=1;
                if count % 1000 == 0 {
                    match measure_size{
                        1 => print!("\rScanning Progress: {}%", (count * 100 / total_count)),
                        2 => print!("\rScanning Progress: {}%", (scanned_bytes * 100 / total_count)),
                        _ => print!("\rScanning Progress: {} , {} files", format_bytes(scanned_bytes), count),
                    };
                    io::stdout().flush().ok();
                }
            }
        }
    }
    total_count = count;

   match measure_size{
        1 => print!("\rScanning Progress: {}%", (count * 100 / total_count)),
        2 => print!("\rScanning Progress: {}%", (scanned_bytes * 100 / total_count)),
        _ => print!("\rScanning Progress: {} bytes, {} files", format_bytes(scanned_bytes), count),
    };
    println!("Zeit: {:.2?}", start.elapsed());

    return Ok(file_actions);
}


fn copy_with_progress(src: &Path, dest: &Path) -> std::io::Result<u64> {
   let file_in = File::open(src)?;
    let file_out = File::create(dest)?;
    
    let mut reader = BufReader::with_capacity(1024 * 1024, file_in);
    let mut writer = BufWriter::with_capacity(1024 * 1024, file_out);

    let meta = fs::metadata(&src)?;
    let total_size = meta.len();
    
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut total: u64 = 0;
    
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 { break; }
        
        writer.write_all(&buffer[..bytes_read])?;
        total += bytes_read as u64;
        
        let percent = (total * 100) / total_size;
        print!("\r{:>3}% - {} / {} bytes    ", percent, total, total_size);
        io::stdout().flush()?;
    }
    
    Ok(total)
}


#[cfg(windows)]
fn copy_with_progress_fast(
    src: &Path,
    dest: &Path,
    progress_callback: &dyn Fn(u64, u64),
) -> std::io::Result<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::CopyFileExW;

    // Speichern als rohe Pointer ohne Lifetime-Info
    static mut CALLBACK_PTR: *const () = std::ptr::null();
    static mut CALLBACK_VTABLE: *const () = std::ptr::null();

    // Trait object in data + vtable pointer zerlegen
    unsafe {
        let raw: (*const (), *const ()) = std::mem::transmute(progress_callback);
        CALLBACK_PTR = raw.0;
        CALLBACK_VTABLE = raw.1;
    }

    unsafe extern "system" fn progress_routine(
        total_file_size: i64,
        total_bytes_transferred: i64,
        _stream_size: i64,
        _stream_bytes_transferred: i64,
        _stream_number: u32,
        _callback_reason: u32,
        _source_file: isize,
        _destination_file: isize,
        _data: *const std::ffi::c_void,
    ) -> u32 {
        unsafe {
            if !CALLBACK_PTR.is_null() {
                // Pointer zurück zu trait object zusammenbauen
                let callback: &dyn Fn(u64, u64) = std::mem::transmute((CALLBACK_PTR, CALLBACK_VTABLE));
                callback(total_bytes_transferred as u64, total_file_size as u64);
            }
        }
        0
    }

    let src_wide: Vec<u16> = src
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();

    let dest_wide: Vec<u16> = dest
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let result = unsafe {
        CopyFileExW(
            src_wide.as_ptr(),
            dest_wide.as_ptr(),
            Some(progress_routine),
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
        )
    };

    // Aufräumen
    unsafe {
        CALLBACK_PTR = std::ptr::null();
        CALLBACK_VTABLE = std::ptr::null();
    }

    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(std::fs::metadata(src)?.len())
    }
}

fn copy_files(file_actions: &Vec<FileAction>) -> std::io::Result<u64> {
   
    //let file_actions = compare_directories(src, dest, false)?;

    // find total size and number of files
    println!("{} Dateien zu kopieren", file_actions.len());
    let total_bytes: u64 = file_actions.iter().map(|a| a.size).sum();

    match total_bytes {
        ..1_000_000_000 => println!("Gesamtgröße: {} MB", total_bytes / 1_000_000),
        _ => println!("Gesamtgröße: {:.1} GB", total_bytes / 1_000_000_000),
    }
    
    let mut copied_bytes:u64 = 0;
    let mut copied_files: u64 = 1; let total_files: u64 = file_actions.len() as u64;
    let one_percent_files : u64 = if file_actions.len() > 1000 {file_actions.len() as u64 /1000} else {1};
    let one_percent_bytes : u64 = total_bytes /1000;
    let mut last_copied_bytes = 0;
    let mut speed: f32 = 0.0;
    let mut start = Instant::now();
    

    for file in file_actions {

        let needs_confirmation = matches!(file.reason, CopyReason::SizeDiffers | CopyReason::Modified);
        if needs_confirmation && !ask_user(&format!("Overwrite \"{}\"?", file.dest_path.display())) {continue;}

        if let Some(parent_path) = file.dest_path.parent() {
            fs::create_dir_all(parent_path)?;
        }

        let size = fs::copy(&file.source_path, &file.dest_path)?;

        // let size = copy_with_progress(&file.source_path, &file.dest_path)?;

        // let size = copy_with_progress_fast(&file.source_path, &file.dest_path, &|copied, total|{
        // let percent = (copied * 100) / total;
        // print!("\r{}% - {} / {} bytes", percent, copied, total);
        // std::io::stdout().flush().ok();
        //})?;


        copied_bytes += size;

       // speed calculations
        let diff = start.elapsed().as_secs_f32();
        if diff > 1.0 {
            speed = (copied_bytes - last_copied_bytes) as f32 / diff;
            last_copied_bytes = copied_bytes;
            start = Instant::now();
        }
    
        
        // print progress
        if copied_files % one_percent_files == 0 || copied_bytes % one_percent_bytes == 0{ 
            let _ = print_progress(copied_bytes, total_bytes, copied_files, total_files, speed, 0.0); 
        }

        copied_files +=1;
    }

    if total_bytes > 0 {let _ = print_progress(copied_bytes, total_bytes, copied_files, total_files, 0.0, 0.0); }

    return Ok(copied_bytes);
   
}


fn copy_files_parallel(file_actions: &Vec<FileAction>) -> std::io::Result<u64> {

    // find total size and number of files
    println!("{} Dateien zu kopieren", file_actions.len());
    let total_bytes: u64 = file_actions.iter().map(|a| a.size).sum();
    

    match total_bytes {
        ..1_000_000_000 => println!("Gesamtgröße: {} MB", total_bytes / 1_000_000),
        _ => println!("Gesamtgröße: {:.1} GB", total_bytes / 1_000_000_000),
    }

    let copied_bytes = Arc::new(AtomicU64::new(0));
    let copied_files = Arc::new(AtomicU64::new(0));
    let total_files = file_actions.len() as u64;
    let done = Arc::new(AtomicBool::new(false));


    // start Progress-Thread
    let progress_handle = {
        let copied_bytes = Arc::clone(&copied_bytes);
        let copied_files = Arc::clone(&copied_files);
        let done = Arc::clone(&done);

        thread::spawn(move || {
            let mut last_bytes: u64 = 0;
            let mut last_time = Instant::now();
            let total_time = Instant::now();

            while !done.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(1000));

                let bytes = copied_bytes.load(Ordering::Relaxed);
                let files = copied_files.load(Ordering::Relaxed);

                let diff = last_time.elapsed().as_secs_f32();
                let speed = if diff > 0.0 {
                    (bytes - last_bytes) as f32 / diff
                } else {
                    0.0
                };

                print_progress(bytes, total_bytes, files, total_files, speed, total_time.elapsed().as_secs_f32());

                last_bytes = bytes;
                last_time = Instant::now();
            }

            // Finale Ausgabe
            let bytes = copied_bytes.load(Ordering::Relaxed);
            let files = copied_files.load(Ordering::Relaxed);
            print_progress(bytes, total_bytes, files, total_files, 0.0, 0.0);
            println!();
        })
    };


    file_actions.par_iter().for_each(|file| {
        //let needs_confirmation = matches!(file.reason, CopyReason::SizeDiffers | CopyReason::Modified);
        //if needs_confirmation && !ask_user(&format!("Overwrite \"{}\"?", file.dest_path.display())) {continue;}

        if let Some(parent) = file.dest_path.parent() {
            fs::create_dir_all(parent).ok();
        }

        if let Ok(size) = fs::copy(&file.source_path, &file.dest_path) {
            copied_bytes.fetch_add(size, Ordering::Relaxed);
            let files = copied_files.fetch_add(1, Ordering::Relaxed) + 1;
            
        }
    });


   // kill Progress-Thread
    done.store(true, Ordering::Relaxed);
    progress_handle.join().ok();

    Ok(copied_bytes.load(Ordering::Relaxed))
}

fn print_progress(copied_bytes: u64, total_bytes: u64, count : u64, total_file: u64, speed: f32, elapsed_time: f32) -> Result<(), Box<dyn std::error::Error>>{

    let percent:u64 = match total_bytes{
        0 => 100,
        _ => (copied_bytes * 100) / total_bytes,
    };

    let copied_str = format_bytes(copied_bytes);
    let total_str = format_bytes(total_bytes);

    let speed_str = format_speed(speed);
    let remaining_time = (total_bytes - copied_bytes) as f32 / (copied_bytes as f32 / elapsed_time); 
    let remaining_time_str = format_time(remaining_time);

    print!("\r{:>3}% - {} / {} - {} / {} Files - Current Speed: {} - Elapsed Time: {} - Expected remaining time: {}", percent, copied_str, total_str, count, total_file, speed_str ,elapsed_time, remaining_time_str);
    io::stdout().flush()?;
    Ok(())
}

fn format_speed(bytes_per_sec: f32) -> String {
    match bytes_per_sec {
        s if s >= 1_000_000_000.0 => format!("{:.2} GB/s", s / 1_000_000_000.0),
        s if s >= 1_000_000.0 => format!("{:.2} MB/s", s / 1_000_000.0),
        s if s >= 1_000.0 => format!("{:.2} KB/s", s / 1_000.0),
        s => format!("{:.0} B/s", s),
    }
}

fn format_bytes(bytes: u64) -> String {
    match bytes {
        ..1_000_000 => format!("{} KB", bytes / 1_000),
        ..1_000_000_000 => format!("{} MB", bytes / 1_000_000),
        _ => format!("{:.1} GB", bytes as f64 / 1_000_000_000.0),
    }
}

fn format_time(secs: f32) -> String {
    if secs < 60.0 {
        format!("{:.1}s", secs)
    } else if secs < 3600.0 {
        let mins = (secs / 60.0) as u32;
        let secs = secs % 60.0;
        format!("{}m", mins)
    }
    else if secs > 864400.0 {
        format!("More than a day")
    }
    else {
        let hours = (secs / 3600.0) as u32;
        let mins = ((secs % 3600.0) / 60.0) as u32;
        format!("{}h {}m", hours, mins)
    }
}

fn ask_user(question : &str) -> bool{
   
    loop {
        println!("{}", question);

        let mut answer = String::new();

        io::stdin()
            .read_line(&mut answer)
            .expect("Failed to read line");
        let answer = answer.trim();

        match answer.trim() {
        "j" => return true,
        "n" => return false,
        _ => println!("Bitte 'j' oder 'n' eingeben"),
        }
    }
   
   
}

// TO DO:
// Estimated time, flags

fn main() {

   
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut num_threads: usize = 0;
    let physical_cores = num_cpus::get_physical();

    let mut cheksum : bool = false;
    let mut measure_size = 0;


    let flags: Vec<&String> = args
        .iter()
        .filter(|arg| arg.starts_with("--"))
        .collect();


    for flag in flags {
        let clean = flag.strip_prefix("--").unwrap_or(flag);

        match clean {
            "cs" => cheksum = true,
            "countBytes" => measure_size = 2,
            "countFiles" => measure_size = 1,
            x => num_threads = x.parse().unwrap(),
        };
    }

    let paths: Vec<&String> = args
        .iter()
        .filter(|arg| !arg.starts_with("--"))
        .collect();

    let dest = PathBuf::from(paths.last().unwrap());

    let sources: Vec<PathBuf> = paths[..paths.len()-1]
        .iter()
        .map(PathBuf::from)
        .collect();

    
    if num_threads == 0 { num_threads = physical_cores;}


    ThreadPoolBuilder::new()
    .num_threads(num_threads)
    .build_global()
    .unwrap();


    println!("{}", num_threads);
    
    test_fnc(&sources, &dest, measure_size);
    
} 

fn test_fnc(sources: &Vec<PathBuf> , dest: &PathBuf, measure_size: u8)  -> Result<(), Box<dyn std::error::Error>>{

    let start = Instant::now();
    let mut all_file_actions = Vec::<FileAction>::new();

    for src in sources {
        let dest_path = dest.join(&src.file_name().unwrap());
        
        let mut actions = compare_directories(&src, &dest_path, false, measure_size)?;
       
        all_file_actions.append(&mut actions);
        
    }

    match copy_files_parallel(&all_file_actions) {
        Ok(res) => {
            let time = start.elapsed();
            let bytes_per_second = res as f32 / time.as_secs_f32();
            println!("\nAverage download speed: {}", format_speed(bytes_per_second));
            println!("Zeit: {:.2?}", start.elapsed());},

        Err(e) => eprintln!("Fehler: {}", e),
    }
    Ok(())
   
}

