// Enhanced file signatures for BruteShark Studio
// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// Ported from NetworkMiner, Scalpel, and custom research
using System.Collections.Generic;

namespace PcapAnalyzer
{
    /// <summary>
    /// Comprehensive file signature database with 50+ file types.
    /// Each entry: (header hex, footer hex, extension, description)
    /// Some file types use multiple signatures for different variants.
    /// </summary>
    public static class EnhancedFileSignatures
    {
        public static List<FileSignature> AllSignatures { get; } = new List<FileSignature>
        {
            // === IMAGES ===
            new FileSignature("FFD8FF", "FFD9", "jpg", "JPEG Image"),
            new FileSignature("FFD8FFE0", "FFD9", "jpg", "JPEG JFIF Image"),
            new FileSignature("FFD8FFE1", "FFD9", "jpg", "JPEG EXIF Image"),
            new FileSignature("89504E470D0A1A0A", "49454E44AE426082", "png", "PNG Image"),
            new FileSignature("474946383761", "003B", "gif", "GIF87a Image"),
            new FileSignature("474946383961", "00003B", "gif", "GIF89a Image"),
            new FileSignature("424D", null, "bmp", "Windows Bitmap"),
            new FileSignature("49492A00", null, "tif", "TIFF Little Endian"),
            new FileSignature("4D4D002A", null, "tif", "TIFF Big Endian"),
            new FileSignature("52494646", null, "webp", "WebP Image"),
            new FileSignature("00000100", null, "ico", "Windows Icon"),
            
            // === VIDEO/AUDIO ===
            new FileSignature("000001BA", "000001B9", "mpg", "MPEG Video"),
            new FileSignature("000001B3", "000001B7", "mpg", "MPEG Video"),
            new FileSignature("1A45DFA3", null, "webm", "WebM/Matroska"),
            new FileSignature("00000018667479706D703432", null, "mp4", "MP4 Video"),
            new FileSignature("0000002066747970", null, "mp4", "MP4 Video (generic)"),
            new FileSignature("52494646", null, "avi", "AVI Video (RIFF header)"),
            new FileSignature("3026B2758E66CF11", null, "wmv", "Windows Media Video"),
            new FileSignature("464C5601", null, "flv", "Flash Video"),
            new FileSignature("494433", null, "mp3", "MP3 Audio"),
            new FileSignature("FFF1", null, "aac", "AAC Audio"),
            new FileSignature("4F676753", null, "ogg", "Ogg Vorbis"),
            new FileSignature("664C6143", null, "flac", "FLAC Audio"),
            new FileSignature("57415645666D7420", null, "wav", "WAV Audio"),
            
            // === ARCHIVES ===
            new FileSignature("504B0304", null, "zip", "ZIP Archive"),
            new FileSignature("504B0506", null, "zip", "ZIP Archive (empty)"),
            new FileSignature("504B0708", null, "zip", "ZIP Archive (spanned)"),
            new FileSignature("526172211A0700", null, "rar", "RAR Archive v4"),
            new FileSignature("526172211A070100", null, "rar", "RAR Archive v5"),
            new FileSignature("377ABCAF271C", null, "7z", "7-Zip Archive"),
            new FileSignature("1F8B08", null, "gz", "GZip Archive"),
            new FileSignature("FD377A585A00", null, "xz", "XZ Archive"),
            new FileSignature("425A68", null, "bz2", "BZip2 Archive"),
            new FileSignature("7573746172", null, "tar", "TAR Archive"),
            
            // === DOCUMENTS (Office / OpenDocument) ===
            new FileSignature("D0CF11E0A1B11AE1", null, "doc", "MS Office OLE2 (doc/xls/ppt)"),
            new FileSignature("504B030414000600", null, "docx", "Office Open XML Document"),
            new FileSignature("255044462D", "2525454F46", "pdf", "PDF Document"),
            new FileSignature("3C3F786D6C20", null, "xml", "XML Document"),
            new FileSignature("EFBBBF", null, "txt", "UTF-8 Text with BOM"),
            
            // === EXECUTABLES ===
            new FileSignature("4D5A", null, "exe", "Windows PE Executable"),
            new FileSignature("7F454C46", null, "elf", "ELF Executable/Library"),
            new FileSignature("FEEDFACE", null, "macho", "Mach-O Binary (32-bit)"),
            new FileSignature("FEEDFACF", null, "macho", "Mach-O Binary (64-bit)"),
            new FileSignature("CAFEBABE", null, "class", "Java Class File"),
            new FileSignature("4D534346", null, "cab", "Microsoft CAB File"),
            
            // === EMAIL ===
            new FileSignature("46726F6D", null, "eml", "Email Message"),
            new FileSignature("52657475726E2D50", null, "eml", "Email (Return-Path)"),
            new FileSignature("4D6963726F736F6674204D61696C", null, "msg", "Outlook MSG File"),
            
            // === CERTIFICATES & KEYS ===
            new FileSignature("3082", null, "der", "X.509 Certificate (DER)"),
            new FileSignature("2D2D2D2D2D424547494E2043455254", null, "pem", "PEM Certificate"),
            new FileSignature("2D2D2D2D2D424547494E20505249", null, "key", "PEM Private Key"),
            new FileSignature("2D2D2D2D2D424547494E20525341", null, "key", "PEM RSA Private Key"),
            
            // === DATABASES ===
            new FileSignature("53514C69746520666F726D61742033", null, "sqlite", "SQLite Database"),
            
            // === SCRIPTS ===
            new FileSignature("23212F62696E2F", null, "sh", "Shell Script"),
            new FileSignature("3C68746D6C", null, "html", "HTML Document"),
            new FileSignature("3C21444F43545950452068746D6C", null, "html", "HTML5 Document"),
            
            // === OTHER ===
            new FileSignature("38425053", null, "psd", "Photoshop PSD"),
            new FileSignature("252150532D41646F6265", null, "eps", "Encapsulated PostScript"),
            new FileSignature("4D4C5357", null, "mls", "Miles Sound System"),
            new FileSignature("89504E470D0A1A0A", null, "apng", "Animated PNG"),
        };
    }

    public class FileSignature
    {
        public string Header { get; }
        public string Footer { get; }
        public string Extension { get; }
        public string Description { get; }

        public FileSignature(string header, string footer, string extension, string description)
        {
            Header = header;
            Footer = footer;
            Extension = extension;
            Description = description;
        }
    }
}
