-- BruteShark Studio Wireshark integration.
--
-- Wireshark Lua plugins cannot load the BruteShark .NET assemblies in-process.
-- This plugin invokes BruteSharkDesktopStudioCli.exe against saved capture files and shows
-- the CLI output in a Wireshark text window.

local plugin_info = {
    version = "0.1.0",
    author = "Ayman Elbanhawy / Softwaremile.com",
    description = "Run BruteShark Studio analysis from Wireshark"
}

set_plugin_info(plugin_info)

local DEFAULT_CLI = [[C:\SourceCode\WireSharkTools\BruteSharkStudio\BruteSharkStudio\BruteSharkCli\bin\Debug\net8.0\BruteSharkDesktopStudioCli.exe]]
local DEFAULT_MODULES = "Credentials,NetworkMap,FileExtracting,DNS,Voip"
local DEFAULT_OUTPUT_DIR = (os.getenv("TEMP") or ".") .. [[\BruteSharkStudioWireshark]]
local PICKER_SCRIPT = [[C:\SourceCode\WireSharkTools\BruteSharkStudio\BruteSharkPlugin\select-captures.ps1]]
local WIRESHARK_CONFIG_DIR = (os.getenv("APPDATA") or "") .. [[\Wireshark]]
local loaded_capture_files = {}

local function file_exists(path)
    if path == nil or path == "" then
        return false
    end

    local f = io.open(path, "rb")
    if f ~= nil then
        f:close()
        return true
    end

    return false
end

local function quote_arg(value)
    value = tostring(value or "")
    return '"' .. value:gsub('"', '\\"') .. '"'
end

local function append_line(lines, text)
    lines[#lines + 1] = text
end

local function trim(value)
    return (value or ""):gsub("^%s+", ""):gsub("%s+$", "")
end

local function normalize_path(path)
    path = trim(path)
    path = path:gsub('^"', ""):gsub('"$', "")
    path = path:gsub("^'", ""):gsub("'$", "")
    return trim(path)
end

local function has_capture_extension(path)
    local lower = path:lower()
    return lower:match("%.pcap$") ~= nil or lower:match("%.pcapng$") ~= nil
end

local function add_capture_file(path, added, rejected)
    path = normalize_path(path)

    if path == "" then
        return
    end

    if not has_capture_extension(path) then
        rejected[#rejected + 1] = path .. "  (not .pcap or .pcapng)"
        return
    end

    if not file_exists(path) then
        rejected[#rejected + 1] = path .. "  (file not found)"
        return
    end

    for _, existing in ipairs(loaded_capture_files) do
        if existing:lower() == path:lower() then
            return
        end
    end

    loaded_capture_files[#loaded_capture_files + 1] = path
    added[#added + 1] = path
end

local function add_capture_path(path, added, rejected)
    path = normalize_path(path)

    if path == "" then
        return
    end

    if has_capture_extension(path) then
        add_capture_file(path, added, rejected)
        return
    end

    if not file_exists(path) then
        rejected[#rejected + 1] = path .. "  (not a capture file)"
        return
    end

    rejected[#rejected + 1] = path .. "  (not .pcap or .pcapng)"
end

local function split_capture_paths(raw_paths)
    local paths = {}
    raw_paths = raw_paths or ""
    raw_paths = raw_paths:gsub("\r", "\n")
    raw_paths = raw_paths:gsub("\n", ";")

    for path in raw_paths:gmatch("[^;]+") do
        paths[#paths + 1] = path
    end

    return paths
end

local function read_lines(path)
    local lines = {}
    local f = io.open(path, "r")

    if f == nil then
        return lines
    end

    for line in f:lines() do
        lines[#lines + 1] = line
    end

    f:close()
    return lines
end

local function get_capture_argument()
    if #loaded_capture_files == 0 then
        return nil
    end

    return table.concat(loaded_capture_files, ",")
end

local function run_command(command)
    local output = {}
    local pipe = io.popen(command .. " 2>&1")

    if pipe == nil then
        return false, "Failed to start command: " .. command
    end

    for line in pipe:lines() do
        output[#output + 1] = line
    end

    local ok, exit_type, exit_code = pipe:close()
    local text = table.concat(output, "\n")

    if ok == true or exit_code == 0 then
        return true, text
    end

    local suffix = ""
    if exit_type ~= nil or exit_code ~= nil then
        suffix = string.format("\n\nProcess result: %s %s", tostring(exit_type), tostring(exit_code))
    end

    return false, text .. suffix
end

local function get_last_recent_capture()
    local recent_common_path = WIRESHARK_CONFIG_DIR .. [[\recent_common]]
    local f = io.open(recent_common_path, "r")

    if f == nil then
        return nil
    end

    local candidate = nil
    for line in f:lines() do
        local path = line:match("^recent%.capture_file:%s*(.+)$")
        if path ~= nil and trim(path) ~= "" then
            candidate = trim(path)
        end
    end

    f:close()

    if file_exists(candidate) then
        return candidate
    end

    return nil
end

local function get_capture_file()
    if type(get_current_capture_file) == "function" then
        local path = get_current_capture_file()
        if file_exists(path) then
            return path, "Wireshark current capture API"
        end
    end

    if type(get_current_capture_filename) == "function" then
        local path = get_current_capture_filename()
        if file_exists(path) then
            return path, "Wireshark current capture filename API"
        end
    end

    local recent_capture = get_last_recent_capture()
    if recent_capture ~= nil then
        return recent_capture, "Wireshark recent capture list"
    end

    return nil, nil
end

local function show_text(title, body)
    local window = TextWindow.new(title)
    window:set(body)
end

local function run_bruteshark(capture_file, modules, output_dir, cli_path, capture_source)
    cli_path = cli_path or DEFAULT_CLI
    modules = modules or DEFAULT_MODULES
    output_dir = output_dir or DEFAULT_OUTPUT_DIR

    local lines = {}
    append_line(lines, "BruteShark Studio Wireshark Plugin")
    append_line(lines, "")

    if not file_exists(cli_path) then
        append_line(lines, "BruteSharkDesktopStudioCli.exe was not found:")
        append_line(lines, cli_path)
        append_line(lines, "")
        append_line(lines, "Build BruteShark Desktop Studio CLI first or use Tools > BruteShark > Configure and run.")
        show_text("BruteShark Studio", table.concat(lines, "\n"))
        return
    end

    if capture_file == nil or capture_file == "" then
        append_line(lines, "No BruteShark Studio capture files are loaded.")
        append_line(lines, "")
        append_line(lines, "Use Tools > BruteShark > Load capture files... and enter one or more .pcap/.pcapng paths.")
        show_text("BruteShark Studio", table.concat(lines, "\n"))
        return
    end

    run_command("mkdir " .. quote_arg(output_dir))

    local command =
        quote_arg(cli_path) ..
        " -m " .. quote_arg(modules) ..
        " -i " .. quote_arg(capture_file) ..
        " -o " .. quote_arg(output_dir)

    append_line(lines, "Capture files:")
    if #loaded_capture_files > 0 and capture_source == "BruteShark loaded file list" then
        for _, path in ipairs(loaded_capture_files) do
            append_line(lines, path)
        end
    else
        append_line(lines, capture_file)
    end
    if capture_source ~= nil and capture_source ~= "" then
        append_line(lines, "Detected from: " .. capture_source)
    end
    append_line(lines, "")
    append_line(lines, "Modules:")
    append_line(lines, modules)
    append_line(lines, "")
    append_line(lines, "Output directory:")
    append_line(lines, output_dir)
    append_line(lines, "")
    append_line(lines, "Command:")
    append_line(lines, command)
    append_line(lines, "")
    append_line(lines, "Running BruteShark Studio...")
    append_line(lines, "")

    local ok, output = run_command(command)
    append_line(lines, output)

    if ok then
        append_line(lines, "")
        append_line(lines, "Finished.")
    else
        append_line(lines, "")
        append_line(lines, "BruteShark Studio returned an error.")
    end

    show_text("BruteShark Studio Results", table.concat(lines, "\n"))
end

local function analyze_current_capture()
    run_bruteshark(get_capture_argument(), DEFAULT_MODULES, DEFAULT_OUTPUT_DIR, DEFAULT_CLI, "BruteShark loaded file list")
end

local function analyze_credentials()
    run_bruteshark(get_capture_argument(), "Credentials", DEFAULT_OUTPUT_DIR, DEFAULT_CLI, "BruteShark loaded file list")
end

local function analyze_network_map()
    run_bruteshark(get_capture_argument(), "NetworkMap,DNS", DEFAULT_OUTPUT_DIR, DEFAULT_CLI, "BruteShark loaded file list")
end

local function load_capture_files()
    new_dialog(
        "Load BruteShark Studio Capture Files",
        function(paths)
            local added = {}
            local rejected = {}

            for _, path in ipairs(split_capture_paths(paths)) do
                add_capture_path(path, added, rejected)
            end

            local lines = {}
            append_line(lines, "BruteShark Studio loaded capture files")
            append_line(lines, "")

            if #added > 0 then
                append_line(lines, "Added:")
                for _, path in ipairs(added) do
                    append_line(lines, path)
                end
                append_line(lines, "")
            end

            if #rejected > 0 then
                append_line(lines, "Skipped:")
                for _, path in ipairs(rejected) do
                    append_line(lines, path)
                end
                append_line(lines, "")
            end

            append_line(lines, "Currently loaded:")
            if #loaded_capture_files == 0 then
                append_line(lines, "(none)")
            else
                for _, path in ipairs(loaded_capture_files) do
                    append_line(lines, path)
                end
            end

            show_text("BruteShark Studio Loaded Captures", table.concat(lines, "\n"))
        end,
        "Capture file paths separated by semicolons"
    )
end

local function load_capture_files_with_picker()
    local added = {}
    local rejected = {}
    local temp_file = (os.getenv("TEMP") or ".") .. [[\BruteSharkWiresharkSelectedCaptures.txt]]
    local lines = {}

    if not file_exists(PICKER_SCRIPT) then
        append_line(lines, "BruteShark Studio capture picker was not found:")
        append_line(lines, PICKER_SCRIPT)
        show_text("BruteShark Studio Capture Picker", table.concat(lines, "\n"))
        return
    end

    local command =
        [[powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File ]] ..
        quote_arg(PICKER_SCRIPT) ..
        [[ -OutputFile ]] ..
        quote_arg(temp_file)

    local ok, output = run_command(command)
    if not ok then
        append_line(lines, "Capture picker failed.")
        append_line(lines, "")
        append_line(lines, output)
        show_text("BruteShark Studio Capture Picker", table.concat(lines, "\n"))
        return
    end

    for _, path in ipairs(read_lines(temp_file)) do
        add_capture_file(path, added, rejected)
    end

    append_line(lines, "BruteShark Studio loaded capture files")
    append_line(lines, "")

    if #added > 0 then
        append_line(lines, "Added:")
        for _, path in ipairs(added) do
            append_line(lines, path)
        end
        append_line(lines, "")
    end

    if #rejected > 0 then
        append_line(lines, "Skipped:")
        for _, path in ipairs(rejected) do
            append_line(lines, path)
        end
        append_line(lines, "")
    end

    if #added == 0 and #rejected == 0 then
        append_line(lines, "No files were selected.")
        append_line(lines, "")
    end

    append_line(lines, "Currently loaded:")
    if #loaded_capture_files == 0 then
        append_line(lines, "(none)")
    else
        for _, path in ipairs(loaded_capture_files) do
            append_line(lines, path)
        end
    end

    show_text("BruteShark Studio Loaded Captures", table.concat(lines, "\n"))
end

local function show_loaded_capture_files()
    local lines = {}
    append_line(lines, "BruteShark Studio loaded capture files")
    append_line(lines, "")

    if #loaded_capture_files == 0 then
        append_line(lines, "No capture files are loaded.")
        append_line(lines, "")
        append_line(lines, "Use Tools > BruteShark > Load capture files...")
    else
        for _, path in ipairs(loaded_capture_files) do
            append_line(lines, path)
        end
    end

    show_text("BruteShark Studio Loaded Captures", table.concat(lines, "\n"))
end

local function clear_loaded_capture_files()
    loaded_capture_files = {}
    show_text("BruteShark Studio Loaded Captures", "BruteShark Studio loaded capture files cleared.")
end

local function configure_and_run()
    new_dialog(
        "Run BruteShark Studio",
        function(capture_file, modules, output_dir, cli_path)
            local capture_source = "dialog"
            if capture_file == nil or capture_file == "" then
                capture_file = get_capture_argument()
                capture_source = "BruteShark loaded file list"
            end
            if modules == nil or modules == "" then
                modules = DEFAULT_MODULES
            end
            if output_dir == nil or output_dir == "" then
                output_dir = DEFAULT_OUTPUT_DIR
            end
            if cli_path == nil or cli_path == "" then
                cli_path = DEFAULT_CLI
            end

            run_bruteshark(capture_file, modules, output_dir, cli_path, capture_source)
        end,
        "Capture file(s), semicolon-separated (blank = loaded list)",
        "Modules (blank = Credentials,NetworkMap,FileExtracting,DNS,Voip)",
        "Output directory (blank = %TEMP%\\BruteSharkStudioWireshark)",
        "BruteSharkDesktopStudioCli.exe (blank = local Debug build)"
    )
end

register_menu("BruteShark/Load capture files or folder...", load_capture_files_with_picker, MENU_TOOLS_UNSORTED)
register_menu("BruteShark/Load capture paths manually...", load_capture_files, MENU_TOOLS_UNSORTED)
register_menu("BruteShark/Show loaded capture files", show_loaded_capture_files, MENU_TOOLS_UNSORTED)
register_menu("BruteShark/Clear loaded capture files", clear_loaded_capture_files, MENU_TOOLS_UNSORTED)
register_menu("BruteShark/Analyze loaded capture files", analyze_current_capture, MENU_TOOLS_UNSORTED)
register_menu("BruteShark/Extract credentials and hashes", analyze_credentials, MENU_TOOLS_UNSORTED)
register_menu("BruteShark/Build network map and DNS", analyze_network_map, MENU_TOOLS_UNSORTED)
register_menu("BruteShark/Configure and run...", configure_and_run, MENU_TOOLS_UNSORTED)
