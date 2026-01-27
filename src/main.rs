use std::fs;
use std::path::Path;
use std::path::PathBuf;
use xxhash_rust::xxh3::xxh3_64;
use std::fs::File;
use std::io::{Read, Write};
use std::io;
use std::time::Instant;
use walkdir::WalkDir;
use std::io::{BufReader, BufWriter};
use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use rayon::ThreadPoolBuilder;



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

fn compare_directories(source: &Path, dest: &Path, checksum: bool) -> Result<Vec<FileAction>, std::io::Error> {

    let start = Instant::now();
    let size = dir_size(source);
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
                  
                    let fa = FileAction {source_path:src_path, dest_path: dest_path, size: meta_src.len(), reason: CopyReason::NewFile,};
                    file_actions.push(fa);
                }

                scanned_bytes += meta_src.len();
                count +=1;
                if count % 1000 == 0 {
                    print!("\rScanning Progress: {}%", (scanned_bytes * 100 / size));
                    io::stdout().flush().ok();
                }
            }
        }
    }

    println!("\rScanning Progress: {}%", (scanned_bytes * 100 / size));
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
            let _ = print_progress(copied_bytes, total_bytes, copied_files, total_files, speed); 
        }

        copied_files +=1;
    }

    if total_bytes > 0 {let _ = print_progress(copied_bytes, total_bytes, copied_files, total_files, 0.0); }

    return Ok(copied_bytes);
   
}


fn copy_files_parallel(file_actions: &Vec<FileAction>) -> std::io::Result<u64> {
    //let file_actions = compare_directories(src, dest, false)?;

    // find total size and number of files
    println!("{} Dateien zu kopieren", file_actions.len());
    let total_bytes: u64 = file_actions.iter().map(|a| a.size).sum();

    match total_bytes {
        ..1_000_000_000 => println!("Gesamtgröße: {} MB", total_bytes / 1_000_000),
        _ => println!("Gesamtgröße: {:.1} GB", total_bytes / 1_000_000_000),
    }

    let copied_bytes = Arc::new(AtomicU64::new(0));
    let copied_files = Arc::new(AtomicU64::new(0));
    let total_files = file_actions.len();
    
    file_actions.par_iter().for_each(|file| {
        if let Some(parent) = file.dest_path.parent() {
            fs::create_dir_all(parent).ok();
        }

        if let Ok(size) = fs::copy(&file.source_path, &file.dest_path) {
            copied_bytes.fetch_add(size, Ordering::Relaxed);
            let files = copied_files.fetch_add(1, Ordering::Relaxed) + 1;
            
            // Progress alle 100 Dateien
            if files % 100 == 0 {
                let bytes = copied_bytes.load(Ordering::Relaxed);
                let percent = (bytes * 100) / total_bytes;
                print!("\r{}% - {} / {} files", percent, files, total_files);
                std::io::stdout().flush().ok();
            }
        }
    });

    println!("\nFertig!");
    Ok(copied_bytes.load(Ordering::Relaxed))
}

fn print_progress(copied_bytes: u64, total_bytes: u64, count : u64, total_file: u64, speed: f32) -> Result<(), Box<dyn std::error::Error>>{

    let percent:u64 = match total_bytes{
        0 => 0,
        _ => (copied_bytes * 100) / total_bytes,
    };

    let (copied_str, total_str) = if total_bytes >= 1_000_000_000 {
            (
                format!("{:.1} GB", copied_bytes as f64 / 1_000_000_000.0),
                format!("{:.1} GB", total_bytes as f64 / 1_000_000_000.0),
            )
    } else {
            (
                format!("{} MB", copied_bytes / 1_000_000),
                format!("{} MB", total_bytes / 1_000_000),
            )
    };

    let speed_str = format_speed(speed);

    print!("\r{:>3}% - {} / {} - {} / {} Files - Current Speed: {}", percent, copied_str, total_str, count, total_file, speed_str );
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
// Estimated time, compression

fn main() {

    ThreadPoolBuilder::new()
    .num_threads(8)
    .build_global()
    .unwrap();

    let args: Vec<String> = std::env::args().skip(1).collect();

    let dest = PathBuf::from(args.last().unwrap());
    let sources: Vec<PathBuf> = args[..args.len()-1]
        .iter()
        .map(PathBuf::from)
        .collect();

    let mut cheksum : bool = false;

    let test = false;
    
    if !test {
        /*println!("Src path: ");
        io::stdin()
        .read_line(&mut src)
        .expect("Failed to read line");

        println!("Dest path: ");
        io::stdin()
        .read_line(&mut dest)
        .expect("Failed to read line");
    
        println!("Use Checksum: ");
        io::stdin()
        .read_line(&mut cheksum)
        .expect("Failed to read line");
        */

        let args: Vec<String> = std::env::args().skip(1).collect();

        let dest = PathBuf::from(args.last().unwrap());
        let sources: Vec<PathBuf> = args[..args.len()-1]
            .iter()
            .map(PathBuf::from)
            .collect();

    } 
    
    test_fnc(&sources, &dest);
    
} 

fn test_fnc(sources: &Vec<PathBuf> , dest: &PathBuf)  -> Result<(), Box<dyn std::error::Error>>{
    println!("{:?}, {:?}",dest, sources);

    let start = Instant::now();
    let mut all_file_actions = Vec::<FileAction>::new();
    for src in sources {
        let dest_path = dest.join(&src.file_name().unwrap());
        
        let mut acttions = compare_directories(&src, &dest_path, false)?;
        all_file_actions.append(&mut acttions);
        
    }

    match copy_files_parallel(&all_file_actions) {
        Ok(res) => {
            let time = start.elapsed();
            let bytes_per_second = res as f32 / time.as_secs_f32();
            println!("Zu kopierende Dateien: {}", format_speed(bytes_per_second));
            println!("Zeit: {:.2?}", start.elapsed());},

        Err(e) => eprintln!("Fehler: {}", e),
    }
    Ok(())
   
}

