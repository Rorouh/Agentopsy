"""Per-wrapper contract tests.

For each catalog wrapper (the 13 core-tier ones plus the EZ Tools absorbed on
2026-07-07 into the extended tier) we exercise:
    - build_argv with valid minimum params returns a list[str] including the
      expected flags / paths.
    - build_argv with missing required params raises ValueError with an
      actionable message.
    - build_argv with invalid values (wrong type, out-of-enum, malformed name)
      raises ValueError.
    - parse with a representative sample stdout returns a dict shaped as the
      wrapper documents.
    - parse with empty stdout returns a dict (no exceptions).

The formerly container-delivered wrappers (regripper / evtxecmd / mftecmd) were
realigned to the maletín exec-agent model: they no longer expose `host_mounts`, and
`build_argv` references the real evidence/output paths instead of `/in/*` mounts.
"""

from __future__ import annotations

import pytest

from forensia.toolkit.wrappers import (
    aff4imager,
    amcacheparser,
    appcompatcacheparser,
    bulk_extractor,
    chainsaw,
    evtxecmd,
    ewf_info,
    foremost,
    ftkimager,
    hashdeep,
    hayabusa,
    jlecmd,
    jq,
    lecmd,
    mftecmd,
    plaso_log2timeline,
    plaso_psort,
    qemu_nbd,
    rbcmd,
    recmd,
    regripper,
    sbecmd,
    tsk_fls,
    tsk_icat,
    tsk_mactime,
    tsk_mmls,
    tsk_recover,
    volatility3,
    wxtcmd,
    yara,
)


# --------------------------------------------------------------------------- #
# tsk_mmls
# --------------------------------------------------------------------------- #
class TestTskMmls:
    def test_build_argv_minimum_valid(self):
        argv = tsk_mmls.build_argv({"image_path": "/tmp/img.raw"})
        assert isinstance(argv, list)
        assert all(isinstance(a, str) for a in argv)
        assert argv[-1] == "/tmp/img.raw"

    def test_build_argv_with_type_and_format(self):
        argv = tsk_mmls.build_argv(
            {"image_path": "/tmp/img.raw", "type": "gpt", "image_format": "ewf"}
        )
        assert "-t" in argv and "gpt" in argv
        assert "-i" in argv and "ewf" in argv

    def test_build_argv_missing_image_path_raises(self):
        with pytest.raises(ValueError, match="image_path"):
            tsk_mmls.build_argv({})

    def test_build_argv_invalid_type_raises(self):
        with pytest.raises(ValueError, match="type"):
            tsk_mmls.build_argv({"image_path": "/x", "type": "ntfs"})

    def test_build_argv_invalid_image_format_raises(self):
        with pytest.raises(ValueError, match="image_format"):
            tsk_mmls.build_argv({"image_path": "/x", "image_format": "iso"})

    def test_build_argv_non_string_image_path_raises(self):
        with pytest.raises(ValueError):
            tsk_mmls.build_argv({"image_path": 42})

    def test_parse_docstring_sample(self):
        sample = (
            "DOS Partition Table\n"
            "Offset Sector: 0\n"
            "Units are in 512-byte sectors\n"
            "\n"
            "     Slot      Start        End          Length       Description\n"
            "000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)\n"
            "001:  -------   0000000000   0000002047   0000002048   Unallocated\n"
            "002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)\n"
        )
        result = tsk_mmls.parse(sample)
        assert result["count"] == 3
        assert {p["slot"] for p in result["partitions"]} == {0, 1, 2}
        ntfs = next(p for p in result["partitions"] if p["slot"] == 2)
        assert ntfs["start_sector"] == 2048
        assert ntfs["length_sectors"] == 204800
        assert "NTFS" in ntfs["description"]

    def test_parse_empty(self):
        out = tsk_mmls.parse("")
        assert out == {"partitions": [], "count": 0}


# --------------------------------------------------------------------------- #
# tsk_fls
# --------------------------------------------------------------------------- #
class TestTskFls:
    def test_build_argv_minimum_valid(self):
        argv = tsk_fls.build_argv({"image_path": "/tmp/img.raw"})
        assert argv == ["/tmp/img.raw"]

    def test_build_argv_partition_offset_zero_is_accepted(self):
        # zero is a legitimate sector offset — `if not value` would wrongly reject it.
        argv = tsk_fls.build_argv({"image_path": "/x", "partition_offset": 0})
        assert "-o" in argv
        assert "0" in argv

    def test_build_argv_negative_offset_rejected(self):
        with pytest.raises(ValueError, match="partition_offset"):
            tsk_fls.build_argv({"image_path": "/x", "partition_offset": -1})

    def test_build_argv_full_flag_set(self):
        argv = tsk_fls.build_argv(
            {
                "image_path": "/x",
                "partition_offset": 2048,
                "filesystem": "ntfs",
                "image_format": "ewf",
                "body_format": True,
                "mount_point": "/c",
                "recursive": True,
                "deleted_only": True,
                "allocated_only": True,
                "long_format": True,
            }
        )
        for flag in ("-o", "-f", "-i", "-m", "-r", "-d", "-u", "-l"):
            assert flag in argv
        assert "ntfs" in argv
        assert "ewf" in argv
        assert "/c" in argv

    def test_build_argv_missing_image_path_raises(self):
        with pytest.raises(ValueError, match="image_path"):
            tsk_fls.build_argv({})

    def test_build_argv_invalid_filesystem_raises(self):
        with pytest.raises(ValueError, match="filesystem"):
            tsk_fls.build_argv({"image_path": "/x", "filesystem": "btrfs"})

    def test_build_argv_invalid_image_format_raises(self):
        with pytest.raises(ValueError, match="image_format"):
            tsk_fls.build_argv({"image_path": "/x", "image_format": "qcow2"})

    def test_build_argv_non_int_offset_raises(self):
        with pytest.raises(ValueError, match="partition_offset"):
            tsk_fls.build_argv({"image_path": "/x", "partition_offset": "2048"})

    def test_parse_list_format(self):
        sample = (
            "r/r 12345: home/user/file.txt\n"
            "d/d 8765: home/user/dir1\n"
        )
        result = tsk_fls.parse(sample)
        assert result["format"] == "list"
        assert result["entries_count"] == 2
        assert result["entries"][0]["type"] == "r/r"
        assert result["entries"][0]["inode"] == "12345"

    def test_parse_body_format(self):
        body = "host|/etc/passwd|123|r/rrwxr-xr-x|0|0|1024|1700000000|1700000000|1700000000|0\n"
        result = tsk_fls.parse(body)
        assert result["format"] == "body"
        assert result["raw"] == body

    def test_parse_empty(self):
        result = tsk_fls.parse("")
        assert isinstance(result, dict)
        assert result["entries_count"] == 0


# --------------------------------------------------------------------------- #
# tsk_mactime
# --------------------------------------------------------------------------- #
class TestTskMactime:
    def test_build_argv_minimum_valid(self):
        argv = tsk_mactime.build_argv({"bodyfile_path": "/tmp/body.txt"})
        assert "-b" in argv
        assert "/tmp/body.txt" in argv
        # -d is always emitted (CSV); -y by default for iso dates
        assert "-d" in argv
        assert "-y" in argv

    def test_build_argv_no_iso_dates(self):
        argv = tsk_mactime.build_argv(
            {"bodyfile_path": "/tmp/body.txt", "iso_dates": False}
        )
        assert "-y" not in argv

    def test_build_argv_with_tz_and_range(self):
        argv = tsk_mactime.build_argv(
            {
                "bodyfile_path": "/b",
                "timezone": "UTC",
                "date_range": "2024-01-01..2024-12-31",
            }
        )
        assert "-z" in argv
        assert "UTC" in argv
        assert "2024-01-01..2024-12-31" in argv

    def test_build_argv_missing_bodyfile_raises(self):
        with pytest.raises(ValueError, match="bodyfile_path"):
            tsk_mactime.build_argv({})

    def test_build_argv_non_string_timezone_raises(self):
        with pytest.raises(ValueError, match="timezone"):
            tsk_mactime.build_argv({"bodyfile_path": "/b", "timezone": 5})

    def test_build_argv_non_string_date_range_raises(self):
        with pytest.raises(ValueError, match="date_range"):
            tsk_mactime.build_argv({"bodyfile_path": "/b", "date_range": 2024})

    def test_parse_sample(self):
        sample = (
            "Date,Size,Type,Mode,UID,GID,Meta,File Name\n"
            "2024-01-15 10:00:00,1024,m...,r/r,0,0,1,/etc/passwd\n"
            "2024-01-15 11:00:00,2048,.a..,r/r,0,0,2,/etc/shadow\n"
            "2024-01-16 09:00:00,512,...b,r/r,0,0,3,/var/log/x\n"
        )
        result = tsk_mactime.parse(sample)
        assert result["rows"] == 3
        assert result["days_count"] == 2
        assert ("2024-01-15", 2) in result["top_days"]
        assert result["first_event"].startswith("2024-01-15 10:00:00")
        assert result["last_event"].startswith("2024-01-16 09:00:00")

    def test_parse_empty(self):
        result = tsk_mactime.parse("")
        assert result["rows"] == 0
        assert result["first_event"] is None
        assert result["last_event"] is None


# --------------------------------------------------------------------------- #
# ewf_info
# --------------------------------------------------------------------------- #
class TestEwfInfo:
    def test_build_argv_minimum_valid(self):
        argv = ewf_info.build_argv({"image_path": "/tmp/img.E01"})
        assert argv == ["/tmp/img.E01"]

    def test_build_argv_missing_raises(self):
        with pytest.raises(ValueError, match="image_path"):
            ewf_info.build_argv({})

    def test_build_argv_non_str_raises(self):
        with pytest.raises(ValueError, match="image_path"):
            ewf_info.build_argv({"image_path": 5})

    def test_parse_with_sections(self):
        sample = (
            "ewfinfo 20140807\n"
            "\n"
            "Acquiry information:\n"
            "\tCase number: CASE-001\n"
            "\tDescription: Suspect drive\n"
            "\n"
            "Media information:\n"
            "\tMedia size: 500 MiB\n"
            "\tBytes per sector: 512\n"
        )
        result = ewf_info.parse(sample)
        # section header lowercased + underscored
        assert "acquiry_information.case_number" in result["fields"]
        assert result["fields"]["acquiry_information.case_number"] == "CASE-001"
        assert "media_information.bytes_per_sector" in result["fields"]
        assert result["count"] == 4

    def test_parse_empty(self):
        result = ewf_info.parse("")
        assert result == {"fields": {}, "count": 0}


# --------------------------------------------------------------------------- #
# bulk_extractor
# --------------------------------------------------------------------------- #
class TestBulkExtractor:
    def test_build_argv_minimum_valid(self):
        argv = bulk_extractor.build_argv(
            {"image_path": "/tmp/img.raw", "output_dir": "/tmp/be_out"}
        )
        assert "-o" in argv
        assert "/tmp/be_out" in argv
        assert "/tmp/img.raw" in argv

    def test_build_argv_enable_and_disable(self):
        argv = bulk_extractor.build_argv(
            {
                "image_path": "/i",
                "output_dir": "/o",
                "enable_scanners": ["email", "url"],
                "disable_scanners": ["aes"],
            }
        )
        assert "-E" in argv and "email" in argv
        assert "-e" in argv and "url" in argv
        assert "-x" in argv and "aes" in argv

    def test_build_argv_missing_image_path_raises(self):
        with pytest.raises(ValueError, match="image_path"):
            bulk_extractor.build_argv({"output_dir": "/o"})

    def test_build_argv_missing_output_dir_raises(self):
        with pytest.raises(ValueError, match="output_dir"):
            bulk_extractor.build_argv({"image_path": "/i"})

    def test_build_argv_invalid_scanner_name_raises(self):
        with pytest.raises(ValueError, match="scanner"):
            bulk_extractor.build_argv(
                {"image_path": "/i", "output_dir": "/o", "enable_scanners": ["evil; rm -rf /"]}
            )

    def test_build_argv_non_list_scanners_raises(self):
        with pytest.raises(ValueError, match="enable_scanners"):
            bulk_extractor.build_argv(
                {"image_path": "/i", "output_dir": "/o", "enable_scanners": "email"}
            )

    def test_parse_with_counts(self):
        sample = (
            "bulk_extractor version: 2.1.0\n"
            "email: 42 features\n"
            "url: 100 features\n"
            "ip: 0 features\n"
        )
        result = bulk_extractor.parse(sample)
        assert result["feature_counts"] == {"email": 42, "url": 100, "ip": 0}
        assert result["total_features"] == 142
        assert "email" in result["scanners_with_hits"]
        assert "ip" not in result["scanners_with_hits"]

    def test_parse_empty(self):
        result = bulk_extractor.parse("")
        assert result == {
            "feature_counts": {},
            "scanners_with_hits": [],
            "total_features": 0,
        }


# --------------------------------------------------------------------------- #
# yara
# --------------------------------------------------------------------------- #
class TestYara:
    def test_build_argv_minimum_valid(self):
        argv = yara.build_argv({"rules_path": "/r.yar", "target_path": "/t"})
        assert argv[-2:] == ["/r.yar", "/t"]

    def test_build_argv_recursive_strings(self):
        argv = yara.build_argv(
            {
                "rules_path": "/r.yar",
                "target_path": "/t",
                "recursive": True,
                "print_strings": True,
                "disable_warnings": True,
            }
        )
        for flag in ("-r", "-s", "-w"):
            assert flag in argv

    def test_build_argv_missing_rules_path_raises(self):
        with pytest.raises(ValueError, match="rules_path"):
            yara.build_argv({"target_path": "/t"})

    def test_build_argv_missing_target_path_raises(self):
        with pytest.raises(ValueError, match="target_path"):
            yara.build_argv({"rules_path": "/r.yar"})

    def test_build_argv_non_str_rules_raises(self):
        with pytest.raises(ValueError, match="rules_path"):
            yara.build_argv({"rules_path": 42, "target_path": "/t"})

    def test_parse_matches(self):
        sample = (
            "rule_one /tmp/file1.bin\n"
            "    $str1: foo\n"
            "rule_two /tmp/dir/file2.exe\n"
        )
        result = yara.parse(sample)
        assert result["count"] == 2
        rules = {m["rule"] for m in result["matches"]}
        assert rules == {"rule_one", "rule_two"}

    def test_parse_empty(self):
        result = yara.parse("")
        assert result == {"matches": [], "count": 0}


# --------------------------------------------------------------------------- #
# jq
# --------------------------------------------------------------------------- #
class TestJq:
    def test_build_argv_minimum_valid(self):
        argv = jq.build_argv({"filter": ".name", "input_path": "/in.json"})
        assert argv == [".name", "/in.json"]

    def test_build_argv_all_flags(self):
        argv = jq.build_argv(
            {
                "filter": ".",
                "input_path": "/x",
                "raw_output": True,
                "compact": True,
                "slurp": True,
                "sort_keys": True,
            }
        )
        for flag in ("-r", "-c", "-s", "-S"):
            assert flag in argv

    def test_build_argv_missing_filter_raises(self):
        with pytest.raises(ValueError, match="filter"):
            jq.build_argv({"input_path": "/x"})

    def test_build_argv_missing_input_raises(self):
        with pytest.raises(ValueError, match="input_path"):
            jq.build_argv({"filter": "."})

    def test_build_argv_filter_too_long_raises(self):
        big = "." * 5000
        with pytest.raises(ValueError, match="too long"):
            jq.build_argv({"filter": big, "input_path": "/x"})

    def test_parse_json(self):
        result = jq.parse('{"a": 1}')
        assert result == {"json": {"a": 1}}

    def test_parse_non_json_raw(self):
        result = jq.parse("hello\nworld\n")
        assert result["raw"] == "hello\nworld\n"
        assert result["lines"] == 2

    def test_parse_empty(self):
        result = jq.parse("")
        assert isinstance(result, dict)
        assert result.get("raw") == "" or "json" in result


# --------------------------------------------------------------------------- #
# volatility3
# --------------------------------------------------------------------------- #
class TestVolatility3:
    def test_build_argv_minimum_valid(self):
        argv = volatility3.build_argv(
            {"dump_path": "/m.dmp", "plugin": "windows.pslist.PsList"}
        )
        assert "-f" in argv and "/m.dmp" in argv
        assert "-r" in argv and "json" in argv
        assert "--quiet" in argv
        assert "windows.pslist.PsList" in argv

    def test_build_argv_with_plugin_args(self):
        argv = volatility3.build_argv(
            {
                "dump_path": "/m.dmp",
                "plugin": "windows.pslist.PsList",
                "plugin_args": {"pid": "0"},
            }
        )
        # value "0" must not be silently rejected by truthiness checks
        assert "--pid" in argv
        assert "0" in argv

    def test_build_argv_missing_dump_raises(self):
        with pytest.raises(ValueError, match="dump_path"):
            volatility3.build_argv({"plugin": "windows.pslist.PsList"})

    def test_build_argv_missing_plugin_raises(self):
        with pytest.raises(ValueError, match="plugin"):
            volatility3.build_argv({"dump_path": "/m.dmp"})

    def test_build_argv_invalid_plugin_name_raises(self):
        with pytest.raises(ValueError, match="plugin name"):
            volatility3.build_argv({"dump_path": "/m.dmp", "plugin": "pslist"})

    def test_build_argv_invalid_plugin_args_key_raises(self):
        with pytest.raises(ValueError, match="plugin_arg key"):
            volatility3.build_argv(
                {
                    "dump_path": "/m.dmp",
                    "plugin": "windows.pslist.PsList",
                    "plugin_args": {"--evil": "x"},
                }
            )

    def test_build_argv_non_str_plugin_args_value_raises(self):
        with pytest.raises(ValueError, match="plugin_arg value"):
            volatility3.build_argv(
                {
                    "dump_path": "/m.dmp",
                    "plugin": "windows.pslist.PsList",
                    "plugin_args": {"pid": 0},
                }
            )

    def test_build_argv_non_dict_plugin_args_raises(self):
        with pytest.raises(ValueError, match="plugin_args"):
            volatility3.build_argv(
                {
                    "dump_path": "/m.dmp",
                    "plugin": "windows.pslist.PsList",
                    "plugin_args": ["pid", "0"],
                }
            )

    def test_parse_json_rows(self):
        # Bug 008: parse returns a BOUNDED summary (row_count + columns + capped
        # sample), never the whole array — the full rows live in the run artifact.
        sample = '[{"PID": 4, "Name": "System"}, {"PID": 100, "Name": "explorer.exe"}]'
        result = volatility3.parse(sample)
        assert result["row_count"] == 2
        assert result["sample"][0]["PID"] == 4
        assert result["columns"] == ["Name", "PID"]
        assert result["sample_truncated"] is False
        assert "rows" not in result  # the uncapped array never reaches context

    def test_parse_caps_large_array(self):
        # A big plugin output (e.g. filescan) is capped to _MAX_SAMPLE_ROWS in the
        # context payload; row_count still reflects the true total.
        import json as _json

        big = _json.dumps([{"PID": i, "Name": f"p{i}"} for i in range(500)])
        result = volatility3.parse(big)
        assert result["row_count"] == 500
        assert len(result["sample"]) == volatility3._MAX_SAMPLE_ROWS
        assert result["sample_truncated"] is True

    def test_parse_not_json(self):
        result = volatility3.parse("not json output\nsecond line\n")
        assert "raw" in result
        assert result["lines"] == 2

    def test_parse_empty(self):
        result = volatility3.parse("")
        assert isinstance(result, dict)


# --------------------------------------------------------------------------- #
# hayabusa
# --------------------------------------------------------------------------- #
class TestHayabusa:
    def test_build_argv_minimum_valid(self):
        argv = hayabusa.build_argv(
            {"evtx_dir": "/in/evtx", "output_csv": "/out/h.csv"}
        )
        assert argv[0] == "csv-timeline"
        assert "-d" in argv and "/in/evtx" in argv
        assert "-o" in argv and "/out/h.csv" in argv
        assert "--no-color" in argv

    def test_build_argv_with_min_level(self):
        argv = hayabusa.build_argv(
            {"evtx_dir": "/in", "output_csv": "/o.csv", "min_level": "high"}
        )
        assert "--min-level" in argv
        assert "high" in argv

    def test_build_argv_missing_evtx_dir_raises(self):
        with pytest.raises(ValueError, match="evtx_dir"):
            hayabusa.build_argv({"output_csv": "/o.csv"})

    def test_build_argv_missing_output_csv_raises(self):
        with pytest.raises(ValueError, match="output_csv"):
            hayabusa.build_argv({"evtx_dir": "/in"})

    def test_build_argv_invalid_min_level_raises(self):
        with pytest.raises(ValueError, match="min_level"):
            hayabusa.build_argv(
                {"evtx_dir": "/in", "output_csv": "/o", "min_level": "panic"}
            )

    def test_parse_summary(self):
        sample = (
            "Hayabusa v2.x\n"
            "| event | match |\n"
            "Total events: 1234\n"
            "Total detections: 56\n"
            "Min level: high\n"
        )
        result = hayabusa.parse(sample)
        assert result["summary"]["total_events"] == "1234"
        assert result["summary"]["total_detections"] == "56"
        # min-level normalised
        assert result["summary"]["min_level"] == "high"
        assert result["summary_count"] >= 3

    def test_parse_empty(self):
        result = hayabusa.parse("")
        assert result == {"summary": {}, "summary_count": 0}


# --------------------------------------------------------------------------- #
# chainsaw
# --------------------------------------------------------------------------- #
class TestChainsaw:
    def test_build_argv_minimum_valid(self):
        argv = chainsaw.build_argv(
            {
                "target_dir": "/in",
                "sigma_dir": "/sigma",
                "output_format": "json",
                "output_path": "/out.json",
            }
        )
        assert argv[0] == "hunt"
        assert "/in" in argv
        assert "-s" in argv and "/sigma" in argv
        assert "--json" in argv
        assert "--output" in argv and "/out.json" in argv

    def test_build_argv_rules_dir_only(self):
        argv = chainsaw.build_argv(
            {
                "target_dir": "/in",
                "rules_dir": "/rules",
                "output_format": "csv",
                "output_path": "/out.csv",
            }
        )
        assert "-r" in argv
        assert "--csv" in argv

    def test_build_argv_missing_target_dir_raises(self):
        with pytest.raises(ValueError, match="target_dir"):
            chainsaw.build_argv(
                {"sigma_dir": "/s", "output_format": "csv", "output_path": "/o"}
            )

    def test_build_argv_no_rule_source_raises(self):
        with pytest.raises(ValueError, match="sigma_dir, rules_dir or ruleset"):
            chainsaw.build_argv(
                {"target_dir": "/in", "output_format": "csv", "output_path": "/o"}
            )

    def test_build_argv_invalid_output_format_raises(self):
        with pytest.raises(ValueError, match="output_format"):
            chainsaw.build_argv(
                {
                    "target_dir": "/in",
                    "sigma_dir": "/s",
                    "output_format": "xml",
                    "output_path": "/o",
                }
            )

    def test_build_argv_missing_output_format_raises(self):
        with pytest.raises(ValueError, match="output_format"):
            chainsaw.build_argv(
                {"target_dir": "/in", "sigma_dir": "/s", "output_path": "/o"}
            )

    def test_build_argv_missing_output_path_raises(self):
        with pytest.raises(ValueError, match="output_path"):
            chainsaw.build_argv(
                {"target_dir": "/in", "sigma_dir": "/s", "output_format": "csv"}
            )

    def test_parse_summary_from_stderr(self):
        # Bug 007: chainsaw emite el resumen y las líneas `Created X.csv` por STDERR.
        stderr = (
            "[+] Loading detection rules\n"
            "[+] Created credential_access.csv\n"
            "[+] Created lateral_movement.csv\n"
            "[+] 56 Detections found on 56 documents\n"
        )
        result = chainsaw.parse("", stderr)
        assert result["detections"] == 56
        assert result["categories"] == [
            "credential_access.csv",
            "lateral_movement.csv",
        ]

    def test_parse_detection_lines_fallback(self):
        # Sin la línea de resumen, cae al conteo legacy de líneas `[+]`.
        sample = "[*] Loading rules\n[+] Hit one\n[+] Hit two\nrandom\n"
        result = chainsaw.parse(sample)
        assert result["detections"] == 2

    def test_parse_empty(self):
        result = chainsaw.parse("")
        assert result == {"detections": 0, "categories": []}


# --------------------------------------------------------------------------- #
# regripper
# --------------------------------------------------------------------------- #
class TestRegripper:
    def test_build_argv_minimum_valid(self):
        # Realineado al maletín: -r referencia la ruta real de la hive (bajo /evidence),
        # no el mount /in/hive del difunto modelo container-por-tool.
        argv = regripper.build_argv({"hive_path": "/evidence/hives/SYSTEM"})
        assert argv == ["-r", "/evidence/hives/SYSTEM"]

    def test_build_argv_with_plugin(self):
        argv = regripper.build_argv(
            {"hive_path": "/tmp/SYSTEM", "plugin": "compname"}
        )
        assert "-p" in argv and "compname" in argv

    def test_build_argv_with_profile(self):
        argv = regripper.build_argv(
            {"hive_path": "/tmp/SYSTEM", "profile": "system"}
        )
        assert "-f" in argv and "system" in argv

    def test_build_argv_plugin_and_profile_mutually_exclusive(self):
        with pytest.raises(ValueError, match="not both"):
            regripper.build_argv(
                {"hive_path": "/tmp/x", "plugin": "p", "profile": "f"}
            )

    def test_build_argv_list_mode(self):
        argv = regripper.build_argv({"list": True})
        assert argv == ["-l"]

    def test_build_argv_missing_hive_path_raises(self):
        with pytest.raises(ValueError, match="hive_path"):
            regripper.build_argv({})

    def test_build_argv_invalid_plugin_name_raises(self):
        with pytest.raises(ValueError, match="plugin name"):
            regripper.build_argv({"hive_path": "/x", "plugin": "bad name!"})

    def test_build_argv_invalid_profile_name_raises(self):
        with pytest.raises(ValueError, match="profile name"):
            regripper.build_argv({"hive_path": "/x", "profile": "bad name!"})

    def test_parse_basic(self):
        sample = "Launching system\nComputerName: WIN-EVIL\n"
        result = regripper.parse(sample)
        assert result["lines"] == 2
        assert result["looks_empty"] is False
        assert "ComputerName" in result["raw"]

    def test_parse_empty(self):
        result = regripper.parse("")
        assert result["lines"] == 0
        assert result["looks_empty"] is True

    def test_no_legacy_host_mounts(self):
        # Realineado al maletín: ya no hay host_mounts (modelo container-por-tool muerto).
        assert not hasattr(regripper, "host_mounts")


# --------------------------------------------------------------------------- #
# evtxecmd
# --------------------------------------------------------------------------- #
class TestEvtxECmd:
    def test_build_argv_single_file(self):
        argv = evtxecmd.build_argv(
            {"evtx_path": "/evidence/Security.evtx", "output_dir": "/tmp/out"}
        )
        # single .evtx selects -f; realineado al maletín: rutas reales, no /in/evtx·/out
        assert "-f" in argv
        assert "/evidence/Security.evtx" in argv
        assert "--csv" in argv and "/tmp/out" in argv
        assert "--csvf" in argv and "evtx.csv" in argv

    def test_build_argv_directory(self):
        argv = evtxecmd.build_argv(
            {"evtx_path": "/evidence/logs", "output_dir": "/tmp/out"}
        )
        # no .evtx suffix → -d
        assert "-d" in argv and "/evidence/logs" in argv

    def test_build_argv_missing_evtx_path_raises(self):
        with pytest.raises(ValueError, match="evtx_path"):
            evtxecmd.build_argv({"output_dir": "/o"})

    def test_build_argv_missing_output_dir_raises(self):
        with pytest.raises(ValueError, match="output_dir"):
            evtxecmd.build_argv({"evtx_path": "/x.evtx"})

    def test_build_argv_non_str_evtx_path_raises(self):
        with pytest.raises(ValueError, match="evtx_path"):
            evtxecmd.build_argv({"evtx_path": 42, "output_dir": "/o"})

    def test_parse_summary(self):
        sample = (
            "EvtxECmd version 1.4.0\n"
            "Processed 1234 events from 5 file(s)\n"
            "Errors: 0\n"
            "Duration: 00:00:10\n"
        )
        result = evtxecmd.parse(sample)
        assert result["summary"]["processed"].startswith("Processed 1234")
        assert result["summary"]["errors"] == "0"
        assert result["summary_count"] >= 2

    def test_parse_empty(self):
        result = evtxecmd.parse("")
        assert result == {"summary": {}, "summary_count": 0}

    def test_no_legacy_host_mounts(self):
        # Realineado al maletín: ya no hay host_mounts (modelo container-por-tool muerto).
        assert not hasattr(evtxecmd, "host_mounts")


# --------------------------------------------------------------------------- #
# mftecmd
# --------------------------------------------------------------------------- #
class TestMftECmd:
    def test_build_argv_minimum_valid(self):
        argv = mftecmd.build_argv({"mft_path": "/evidence/mft/$MFT", "output_dir": "/tmp/o"})
        # realineado al maletín: rutas reales, no /in/mft·/out
        assert "-f" in argv and "/evidence/mft/$MFT" in argv
        assert "--csv" in argv and "/tmp/o" in argv
        assert "--csvf" in argv and "mft.csv" in argv

    def test_build_argv_missing_mft_path_raises(self):
        with pytest.raises(ValueError, match="mft_path"):
            mftecmd.build_argv({"output_dir": "/o"})

    def test_build_argv_missing_output_dir_raises(self):
        with pytest.raises(ValueError, match="output_dir"):
            mftecmd.build_argv({"mft_path": "/x"})

    def test_build_argv_non_str_mft_path_raises(self):
        with pytest.raises(ValueError, match="mft_path"):
            mftecmd.build_argv({"mft_path": 5, "output_dir": "/o"})

    def test_parse_summary(self):
        sample = (
            "MFTECmd version 1.2.0\n"
            "Processed 50000 MFT records\n"
            "Errors: 2\n"
        )
        result = mftecmd.parse(sample)
        assert result["summary"]["processed"].startswith("Processed 50000")
        assert result["summary"]["errors"] == "2"

    def test_parse_empty(self):
        result = mftecmd.parse("")
        assert result == {"summary": {}, "summary_count": 0}

    def test_no_legacy_host_mounts(self):
        # Realineado al maletín: ya no hay host_mounts (modelo container-por-tool muerto).
        assert not hasattr(mftecmd, "host_mounts")


# --------------------------------------------------------------------------- #
# lecmd
# --------------------------------------------------------------------------- #
class TestLECmd:
    def test_build_argv_single_file(self):
        argv = lecmd.build_argv(
            {"target_path": "/evidence/Recent/doc.lnk", "output_dir": "/tmp/out"}
        )
        assert "-f" in argv and "/evidence/Recent/doc.lnk" in argv
        assert "--csv" in argv and "/tmp/out" in argv

    def test_build_argv_directory(self):
        argv = lecmd.build_argv({"target_path": "/evidence/Recent", "output_dir": "/tmp/out"})
        assert "-d" in argv and "/evidence/Recent" in argv

    def test_build_argv_missing_target_path_raises(self):
        with pytest.raises(ValueError, match="target_path"):
            lecmd.build_argv({"output_dir": "/o"})

    def test_build_argv_missing_output_dir_raises(self):
        with pytest.raises(ValueError, match="output_dir"):
            lecmd.build_argv({"target_path": "/x.lnk"})

    def test_build_argv_non_str_target_path_raises(self):
        with pytest.raises(ValueError, match="target_path"):
            lecmd.build_argv({"target_path": 42, "output_dir": "/o"})

    def test_parse_summary(self):
        sample = (
            "LECmd version 2026.5.0\n"
            "Processed 3 files\n"
            "Errors: 0\n"
        )
        result = lecmd.parse(sample)
        assert result["summary"]["processed"].startswith("Processed 3")
        assert result["summary"]["errors"] == "0"

    def test_parse_empty(self):
        assert lecmd.parse("") == {"summary": {}, "summary_count": 0}

    def test_no_legacy_host_mounts(self):
        assert not hasattr(lecmd, "host_mounts")


# --------------------------------------------------------------------------- #
# jlecmd
# --------------------------------------------------------------------------- #
class TestJLECmd:
    def test_build_argv_single_file(self):
        argv = jlecmd.build_argv(
            {
                "target_path": "/evidence/Recent/abc.automaticDestinations-ms",
                "output_dir": "/tmp/out",
            }
        )
        assert "-f" in argv
        assert "/evidence/Recent/abc.automaticDestinations-ms" in argv
        assert "--csv" in argv and "/tmp/out" in argv

    def test_build_argv_directory(self):
        argv = jlecmd.build_argv({"target_path": "/evidence/Recent", "output_dir": "/tmp/out"})
        assert "-d" in argv and "/evidence/Recent" in argv

    def test_build_argv_missing_target_path_raises(self):
        with pytest.raises(ValueError, match="target_path"):
            jlecmd.build_argv({"output_dir": "/o"})

    def test_build_argv_missing_output_dir_raises(self):
        with pytest.raises(ValueError, match="output_dir"):
            jlecmd.build_argv({"target_path": "/evidence/Recent"})

    def test_parse_summary(self):
        sample = (
            "JLECmd version 2026.5.0\n"
            "Processed 12 files\n"
            "AutomaticDestinations: 10\n"
        )
        result = jlecmd.parse(sample)
        assert result["summary"]["processed"].startswith("Processed 12")
        assert result["summary"]["automaticdestinations"] == "10"

    def test_parse_empty(self):
        assert jlecmd.parse("") == {"summary": {}, "summary_count": 0}

    def test_no_legacy_host_mounts(self):
        assert not hasattr(jlecmd, "host_mounts")


# --------------------------------------------------------------------------- #
# recmd
# --------------------------------------------------------------------------- #
class TestRECmd:
    def test_build_argv_single_hive(self):
        argv = recmd.build_argv(
            {
                "hive_path": "/evidence/config/SOFTWARE",
                "output_dir": "/tmp/out",
                "batch": "/opt/eztools/RECmd/RECmd/BatchExamples/Kroll_Batch.reb",
            }
        )
        assert "--bn" in argv
        assert "/opt/eztools/RECmd/RECmd/BatchExamples/Kroll_Batch.reb" in argv
        assert "-f" in argv and "/evidence/config/SOFTWARE" in argv
        assert "--csv" in argv and "/tmp/out" in argv

    def test_build_argv_directory(self):
        argv = recmd.build_argv(
            {
                "hive_path": "/evidence/config",
                "output_dir": "/tmp/out",
                "batch": "/opt/eztools/RECmd/RECmd/BatchExamples/Kroll_Batch.reb",
                "is_directory": True,
            }
        )
        assert "-d" in argv and "/evidence/config" in argv

    def test_build_argv_missing_batch_raises(self):
        with pytest.raises(ValueError, match="batch"):
            recmd.build_argv({"hive_path": "/x", "output_dir": "/o"})

    def test_build_argv_missing_hive_path_raises(self):
        with pytest.raises(ValueError, match="hive_path"):
            recmd.build_argv({
                "output_dir": "/o",
                "batch": "/opt/eztools/RECmd/RECmd/BatchExamples/Kroll_Batch.reb",
            })

    def test_build_argv_non_bool_is_directory_raises(self):
        with pytest.raises(ValueError, match="is_directory"):
            recmd.build_argv(
                {
                    "hive_path": "/x",
                    "output_dir": "/o",
                    "batch": "Kroll_Batch.reb",
                    "is_directory": "yes",
                }
            )

    def test_parse_summary(self):
        sample = (
            "RECmd version 2026.5.0\n"
            "Found 618 key/value pairs across 1 file\n"
            "Total search time: 7.049 seconds\n"
        )
        result = recmd.parse(sample)
        assert result["summary"]["total_search_time"].startswith("7.049")

    def test_parse_empty(self):
        assert recmd.parse("") == {"summary": {}, "summary_count": 0}

    def test_no_legacy_host_mounts(self):
        assert not hasattr(recmd, "host_mounts")


# --------------------------------------------------------------------------- #
# amcacheparser
# --------------------------------------------------------------------------- #
class TestAmcacheParser:
    def test_build_argv_minimum_valid(self):
        argv = amcacheparser.build_argv(
            {"hive_path": "/evidence/Programs/Amcache.hve", "output_dir": "/tmp/out"}
        )
        assert "-f" in argv and "/evidence/Programs/Amcache.hve" in argv
        assert "--csv" in argv and "/tmp/out" in argv
        assert "-i" not in argv

    def test_build_argv_include_linked(self):
        argv = amcacheparser.build_argv(
            {
                "hive_path": "/evidence/Programs/Amcache.hve",
                "output_dir": "/tmp/out",
                "include_linked": True,
            }
        )
        assert "-i" in argv

    def test_build_argv_missing_hive_path_raises(self):
        with pytest.raises(ValueError, match="hive_path"):
            amcacheparser.build_argv({"output_dir": "/o"})

    def test_build_argv_non_bool_include_linked_raises(self):
        with pytest.raises(ValueError, match="include_linked"):
            amcacheparser.build_argv(
                {"hive_path": "/x", "output_dir": "/o", "include_linked": "yes"}
            )

    def test_parse_summary(self):
        sample = (
            "AmcacheParser version 2026.5.0\n"
            "Total program entries found: 68\n"
            "Total parsing time: 0.336 seconds\n"
        )
        result = amcacheparser.parse(sample)
        assert result["summary"]["total_program_entries_found"] == "68"

    def test_parse_empty(self):
        assert amcacheparser.parse("") == {"summary": {}, "summary_count": 0}

    def test_no_legacy_host_mounts(self):
        assert not hasattr(amcacheparser, "host_mounts")


# --------------------------------------------------------------------------- #
# appcompatcacheparser
# --------------------------------------------------------------------------- #
class TestAppCompatCacheParser:
    def test_build_argv_minimum_valid(self):
        argv = appcompatcacheparser.build_argv(
            {"hive_path": "/evidence/config/SYSTEM", "output_dir": "/tmp/out"}
        )
        assert "-f" in argv and "/evidence/config/SYSTEM" in argv
        assert "--csv" in argv and "/tmp/out" in argv

    def test_build_argv_missing_hive_path_raises(self):
        with pytest.raises(ValueError, match="hive_path"):
            appcompatcacheparser.build_argv({"output_dir": "/o"})

    def test_build_argv_missing_output_dir_raises(self):
        with pytest.raises(ValueError, match="output_dir"):
            appcompatcacheparser.build_argv({"hive_path": "/x"})

    def test_parse_summary(self):
        sample = (
            "AppCompatCache Parser version 2026.5.0\n"
            "Found 24 cache entries for Windows7x64_Windows2008R2 in ControlSet002\n"
            "Results saved to: /cases/out.csv\n"
        )
        result = appcompatcacheparser.parse(sample)
        assert result["summary"]["results_saved_to"] == "/cases/out.csv"

    def test_parse_empty(self):
        assert appcompatcacheparser.parse("") == {"summary": {}, "summary_count": 0}

    def test_no_legacy_host_mounts(self):
        assert not hasattr(appcompatcacheparser, "host_mounts")


# --------------------------------------------------------------------------- #
# sbecmd
# --------------------------------------------------------------------------- #
class TestSBECmd:
    def test_build_argv_minimum_valid(self):
        argv = sbecmd.build_argv(
            {"target_path": "/evidence/Users/x/AppData/Local/Microsoft/Windows", "output_dir": "/tmp/out"}
        )
        assert "-d" in argv
        assert "/evidence/Users/x/AppData/Local/Microsoft/Windows" in argv
        assert "--csv" in argv and "/tmp/out" in argv

    def test_build_argv_missing_target_path_raises(self):
        with pytest.raises(ValueError, match="target_path"):
            sbecmd.build_argv({"output_dir": "/o"})

    def test_build_argv_missing_output_dir_raises(self):
        with pytest.raises(ValueError, match="output_dir"):
            sbecmd.build_argv({"target_path": "/x"})

    def test_parse_summary(self):
        sample = (
            "SBECmd version 2026.5.0\n"
            "Processed 1 file in 0.17 seconds!\n"
            "Total ShellBags found: 78\n"
        )
        result = sbecmd.parse(sample)
        assert result["summary"]["processed"].startswith("Processed 1 file")
        assert result["summary"]["total_shellbags_found"] == "78"

    def test_parse_empty(self):
        assert sbecmd.parse("") == {"summary": {}, "summary_count": 0}

    def test_no_legacy_host_mounts(self):
        assert not hasattr(sbecmd, "host_mounts")


# --------------------------------------------------------------------------- #
# wxtcmd
# --------------------------------------------------------------------------- #
class TestWxTCmd:
    def test_build_argv_minimum_valid(self):
        argv = wxtcmd.build_argv(
            {"target_path": "/evidence/CDP/ActivitiesCache.db", "output_dir": "/tmp/out"}
        )
        assert "-f" in argv and "/evidence/CDP/ActivitiesCache.db" in argv
        assert "--csv" in argv and "/tmp/out" in argv

    def test_build_argv_missing_target_path_raises(self):
        with pytest.raises(ValueError, match="target_path"):
            wxtcmd.build_argv({"output_dir": "/o"})

    def test_build_argv_missing_output_dir_raises(self):
        with pytest.raises(ValueError, match="output_dir"):
            wxtcmd.build_argv({"target_path": "/x.db"})

    def test_parse_summary(self):
        sample = (
            "WxTCmd version 2026.5.0\n"
            "Activity entries found: 122\n"
        )
        result = wxtcmd.parse(sample)
        assert result["summary"]["activity_entries_found"] == "122"

    def test_parse_empty(self):
        assert wxtcmd.parse("") == {"summary": {}, "summary_count": 0}

    def test_no_legacy_host_mounts(self):
        assert not hasattr(wxtcmd, "host_mounts")


# --------------------------------------------------------------------------- #
# rbcmd
# --------------------------------------------------------------------------- #
class TestRBCmd:
    def test_build_argv_directory_default(self):
        argv = rbcmd.build_argv(
            {"target_path": "/evidence/$Recycle.Bin", "output_dir": "/tmp/out"}
        )
        assert "-d" in argv and "/evidence/$Recycle.Bin" in argv
        assert "--csv" in argv and "/tmp/out" in argv

    def test_build_argv_single_file(self):
        argv = rbcmd.build_argv(
            {
                "target_path": "/evidence/$Recycle.Bin/S-1-5-21/$IKWQPOX.doc",
                "output_dir": "/tmp/out",
                "is_file": True,
            }
        )
        assert "-f" in argv

    def test_build_argv_missing_target_path_raises(self):
        with pytest.raises(ValueError, match="target_path"):
            rbcmd.build_argv({"output_dir": "/o"})

    def test_build_argv_non_bool_is_file_raises(self):
        with pytest.raises(ValueError, match="is_file"):
            rbcmd.build_argv({"target_path": "/x", "output_dir": "/o", "is_file": 1})

    def test_parse_summary(self):
        sample = (
            "RBCmd version 2026.5.0\n"
            "Processed 2 out of 2 files in 0.0467 seconds\n"
        )
        result = rbcmd.parse(sample)
        assert result["summary"]["processed"].startswith("Processed 2 out of 2")

    def test_parse_empty(self):
        assert rbcmd.parse("") == {"summary": {}, "summary_count": 0}

    def test_no_legacy_host_mounts(self):
        assert not hasattr(rbcmd, "host_mounts")


# --------------------------------------------------------------------------- #
# ftkimager
# --------------------------------------------------------------------------- #
class TestFtkImager:
    def test_build_argv_default_raw_with_verify(self):
        argv = ftkimager.build_argv(
            {"image_path": "/evidence/disco.E01", "output_dir": "/tmp/out"}
        )
        assert argv[0] == "/evidence/disco.E01"
        assert argv[1] == "/tmp/out/imagen"
        assert "--quiet" in argv and "--verify" in argv
        # raw es el default de ftkimager: sin flag de formato ni compresión
        assert "--e01" not in argv and "--s01" not in argv and "--compress" not in argv

    def test_build_argv_e01_with_compress(self):
        argv = ftkimager.build_argv(
            {
                "image_path": "/evidence/disco.raw",
                "output_dir": "/tmp/out",
                "format": "e01",
                "compress": 6,
            }
        )
        assert "--e01" in argv
        assert "--compress" in argv and "6" in argv

    def test_build_argv_verify_false_omits_flag(self):
        argv = ftkimager.build_argv(
            {"image_path": "/x.raw", "output_dir": "/o", "verify": False}
        )
        assert "--verify" not in argv

    def test_build_argv_compress_with_raw_raises(self):
        with pytest.raises(ValueError, match="compress"):
            ftkimager.build_argv(
                {"image_path": "/x.raw", "output_dir": "/o", "compress": 6}
            )

    def test_build_argv_compress_out_of_range_raises(self):
        with pytest.raises(ValueError, match="compress"):
            ftkimager.build_argv(
                {"image_path": "/x", "output_dir": "/o", "format": "e01", "compress": 10}
            )

    def test_build_argv_invalid_format_raises(self):
        with pytest.raises(ValueError, match="format"):
            ftkimager.build_argv(
                {"image_path": "/x", "output_dir": "/o", "format": "aff"}
            )

    def test_build_argv_missing_image_path_raises(self):
        with pytest.raises(ValueError, match="image_path"):
            ftkimager.build_argv({"output_dir": "/o"})

    def test_build_argv_missing_output_dir_raises(self):
        with pytest.raises(ValueError, match="output_dir"):
            ftkimager.build_argv({"image_path": "/x.E01"})

    def test_parse_verify_sections(self):
        sample = (
            "Creating image...\n"
            "Image creation complete.\n"
            "[MD5]\n"
            " Computed hash: 43a2b91a24ef7dbb39f2286d07428cc8\n"
            " Report hash:   43a2b91a24ef7dbb39f2286d07428cc8\n"
            " Verify result: Match\n"
            "[SHA1]\n"
            " Computed hash: e2a0e58320d1b0213fa14a3d68f6350ca5b43793\n"
            " Verify result: Match\n"
        )
        result = ftkimager.parse(sample)
        assert result["summary"]["md5_verify_result"] == "Match"
        assert result["summary"]["sha1_computed_hash"].startswith("e2a0e583")
        assert result["verify_results"] == ["Match", "Match"]

    def test_parse_empty(self):
        assert ftkimager.parse("") == {
            "summary": {},
            "verify_results": [],
            "summary_count": 0,
        }

    def test_no_legacy_host_mounts(self):
        assert not hasattr(ftkimager, "host_mounts")


# --------------------------------------------------------------------------- #
# aff4imager
# --------------------------------------------------------------------------- #
class TestAff4Imager:
    def test_build_argv_list_mode_without_stream(self):
        argv = aff4imager.build_argv(
            {"image_path": "/evidence/mem.aff4", "output_dir": "/tmp/out"}
        )
        assert argv == ["-l", "/evidence/mem.aff4"]

    def test_build_argv_export_mode_with_urn(self):
        urn = "aff4://86006c40-b262-4c3b-9dfc-132e58cade93/PhysicalMemory"
        argv = aff4imager.build_argv(
            {"image_path": "/evidence/mem.aff4", "output_dir": "/tmp/out", "stream": urn}
        )
        assert argv == ["-e", urn, "-D", "/tmp/out", "/evidence/mem.aff4"]

    def test_build_argv_stream_without_urn_prefix_raises(self):
        # RULE 2: el stream es el URN literal de un listado previo, nunca un nombre suelto
        with pytest.raises(ValueError, match="aff4://"):
            aff4imager.build_argv(
                {"image_path": "/x.aff4", "output_dir": "/o", "stream": "PhysicalMemory"}
            )

    def test_build_argv_missing_image_path_raises(self):
        with pytest.raises(ValueError, match="image_path"):
            aff4imager.build_argv({"output_dir": "/o"})

    def test_build_argv_missing_output_dir_raises(self):
        with pytest.raises(ValueError, match="output_dir"):
            aff4imager.build_argv({"image_path": "/x.aff4"})

    def test_parse_stream_listing(self):
        sample = (
            "aff4://86006c40-b262-4c3b-9dfc-132e58cade93/PhysicalMemory\n"
            "aff4://86006c40-b262-4c3b-9dfc-132e58cade93/pagefile.sys\n"
        )
        result = aff4imager.parse(sample)
        assert result["stream_count"] == 2
        assert result["streams"][0].endswith("/PhysicalMemory")

    def test_parse_empty(self):
        assert aff4imager.parse("") == {"streams": [], "stream_count": 0, "summary": {}}

    def test_no_legacy_host_mounts(self):
        assert not hasattr(aff4imager, "host_mounts")


# --------------------------------------------------------------------------- #
# hashdeep
# --------------------------------------------------------------------------- #
class TestHashdeep:
    def test_build_argv_minimum_valid(self):
        argv = hashdeep.build_argv({"image_path": "/ev/img.raw"})
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        # default algorithms md5,sha256
        assert argv[:2] == ["-c", "md5,sha256"]
        assert argv[-1] == "/ev/img.raw"

    def test_build_argv_custom_algorithms_and_recursive(self):
        argv = hashdeep.build_argv(
            {"image_path": "/d", "algorithms": ["sha1", "sha256"], "recursive": True}
        )
        assert "-c" in argv and "sha1,sha256" in argv
        assert "-r" in argv
        assert argv[-1] == "/d"

    def test_build_argv_missing_image_path_raises(self):
        with pytest.raises(ValueError, match="image_path"):
            hashdeep.build_argv({})

    def test_build_argv_invalid_algorithm_raises(self):
        with pytest.raises(ValueError, match="algorithm"):
            hashdeep.build_argv({"image_path": "/x", "algorithms": ["crc32"]})

    def test_build_argv_non_list_algorithms_raises(self):
        with pytest.raises(ValueError, match="list"):
            hashdeep.build_argv({"image_path": "/x", "algorithms": "md5"})

    def test_parse_csv_with_header(self):
        sample = (
            "%%%% HASHDEEP-1.0\n"
            "%%%% size,md5,sha256,filename\n"
            "## Invoked from: /cases\n"
            "231,e54785ec,f276816f,/cases/main.sh\n"
            "1859,04f2e2ae,b36cf9f4,/cases/config.inc.php\n"
        )
        out = hashdeep.parse(sample)
        assert out["files_count"] == 2
        assert out["algorithms"] == ["md5", "sha256"]
        first = out["files"][0]
        assert first["path"] == "/cases/main.sh"
        assert first["size"] == "231"
        assert first["hashes"] == {"md5": "e54785ec", "sha256": "f276816f"}

    def test_parse_empty_returns_dict(self):
        out = hashdeep.parse("")
        assert out["files_count"] == 0
        assert out["files"] == []


# --------------------------------------------------------------------------- #
# foremost
# --------------------------------------------------------------------------- #
class TestForemost:
    def test_build_argv_minimum_valid(self):
        argv = foremost.build_argv({"image_path": "/ev/img.raw", "output_dir": "/run/out"})
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        # carves into a FRESH subdir (foremost refuses an existing dir)
        assert "-o" in argv and "/run/out/foremost" in argv
        assert "-i" in argv and "/ev/img.raw" in argv

    def test_build_argv_types_and_quick(self):
        argv = foremost.build_argv(
            {"image_path": "/x", "output_dir": "/o", "types": ["jpg", "pdf"], "quick": True}
        )
        assert "-t" in argv and "jpg,pdf" in argv
        assert "-q" in argv

    def test_build_argv_missing_image_path_raises(self):
        with pytest.raises(ValueError, match="image_path"):
            foremost.build_argv({"output_dir": "/o"})

    def test_build_argv_missing_output_dir_raises(self):
        with pytest.raises(ValueError, match="output_dir"):
            foremost.build_argv({"image_path": "/x"})

    def test_build_argv_invalid_type_raises(self):
        with pytest.raises(ValueError, match="type"):
            foremost.build_argv({"image_path": "/x", "output_dir": "/o", "types": ["iso"]})

    def test_parse_finished_and_markers(self):
        sample = "Processing: /ev/img.raw\nfoundat=abc\nfoundat=def\nForemost finished at 2026\n"
        out = foremost.parse(sample)
        assert out["finished"] is True
        assert out["foundat_markers"] == 2

    def test_parse_empty_returns_dict(self):
        out = foremost.parse("")
        assert out["finished"] is False
        assert out["foundat_markers"] == 0


# --------------------------------------------------------------------------- #
# tsk_icat
# --------------------------------------------------------------------------- #
class TestTskIcat:
    def test_build_argv_minimum_valid(self):
        argv = tsk_icat.build_argv({"image_path": "/ev/img.raw", "inode": 13552})
        assert argv == ["/ev/img.raw", "13552"]

    def test_build_argv_inode_as_tsk_address(self):
        argv = tsk_icat.build_argv({"image_path": "/x", "inode": "12-128-4"})
        assert argv[-1] == "12-128-4"

    def test_build_argv_full_flags(self):
        argv = tsk_icat.build_argv(
            {
                "image_path": "/x",
                "inode": 5,
                "partition_offset": 2048,
                "filesystem": "ext4",
                "image_format": "raw",
                "recover": True,
                "slack": True,
            }
        )
        for flag in ("-o", "-f", "-i", "-r", "-s"):
            assert flag in argv
        assert argv[-2:] == ["/x", "5"]

    def test_build_argv_missing_image_path_raises(self):
        with pytest.raises(ValueError, match="image_path"):
            tsk_icat.build_argv({"inode": 1})

    def test_build_argv_missing_inode_raises(self):
        with pytest.raises(ValueError, match="inode"):
            tsk_icat.build_argv({"image_path": "/x"})

    def test_build_argv_bad_inode_raises(self):
        with pytest.raises(ValueError, match="inode"):
            tsk_icat.build_argv({"image_path": "/x", "inode": "1; rm -rf"})

    def test_build_argv_invalid_filesystem_raises(self):
        with pytest.raises(ValueError, match="filesystem"):
            tsk_icat.build_argv({"image_path": "/x", "inode": 1, "filesystem": "btrfs"})

    def test_parse_text_file(self):
        out = tsk_icat.parse("root:x:0:0:root:/root:/bin/bash\n")
        assert out["is_text"] is True
        assert out["content_length"] > 0
        assert "root" in out["preview"]

    def test_parse_empty(self):
        out = tsk_icat.parse("")
        assert out["content_length"] == 0


# --------------------------------------------------------------------------- #
# plaso_log2timeline
# --------------------------------------------------------------------------- #
class TestPlasoLog2timeline:
    def test_build_argv_minimum_valid(self):
        argv = plaso_log2timeline.build_argv({"image_path": "/ev/img.raw", "output_dir": "/run/out"})
        assert "--storage_file" in argv and "/run/out/timeline.plaso" in argv
        assert "--partitions" in argv and "all" in argv
        assert argv[-1] == "/ev/img.raw"  # SOURCE positional last

    def test_build_argv_partitions_and_parsers(self):
        argv = plaso_log2timeline.build_argv(
            {"image_path": "/x", "output_dir": "/o", "partitions": "1", "parsers": "filestat"}
        )
        assert "--partitions" in argv and "1" in argv
        assert "--parsers" in argv and "filestat" in argv

    def test_build_argv_never_blocks_waiting_for_a_human(self):
        """Las tres banderas que impiden que la corrida se cuelgue (medido 2026-08-05).

        Sobre una imagen de 8 GB con LVM y el maletín emulado (linux/amd64 sobre
        arm64, porque el PPA GIFT no publica arm64):
        1+2. plaso PREGUNTABA por teclado qué volumen LVM procesar y se quedaba
             bloqueado leyendo un stdin que el exec-agent no da, comiéndose los
             1800 s del techo. Sin stdin es peor: no procesa NINGÚN volumen y
             dice «Processing completed» con un .plaso vacío, un falso éxito.
        3.   Ya sin el prompt, el motor multiproceso seguía colgado en
             `futex_wait_queue` con 4 SEGUNDOS de CPU en 20 minutos y cero
             workers. Con las tres, la corrida pasa a 100 % de CPU.
        """
        argv = plaso_log2timeline.build_argv({"image_path": "/x", "output_dir": "/o"})
        assert argv[argv.index("--volumes") + 1] == "all"
        assert "--unattended" in argv
        assert "--single_process" in argv
        assert "--workers" not in argv
        # `--no_vss` está deprecado en plaso 20240308; la forma soportada es esta.
        assert argv[argv.index("--vss_stores") + 1] == "none"
        assert "--no_vss" not in argv

    def test_build_argv_bad_volumes_raises(self):
        with pytest.raises(ValueError, match="volumes"):
            plaso_log2timeline.build_argv(
                {"image_path": "/x", "output_dir": "/o", "volumes": "; rm -rf /"}
            )

    def test_build_argv_workers_is_an_explicit_opt_in(self):
        """Volver al motor que se cuelga es decisión EXPLÍCITA del operador (RULE 2)."""
        argv = plaso_log2timeline.build_argv(
            {"image_path": "/x", "output_dir": "/o", "workers": 4}
        )
        assert argv[argv.index("--workers") + 1] == "4"
        assert "--single_process" not in argv
        # workers=1 es monoproceso, no un multiproceso de un solo worker.
        argv_one = plaso_log2timeline.build_argv(
            {"image_path": "/x", "output_dir": "/o", "workers": 1}
        )
        assert "--single_process" in argv_one and "--workers" not in argv_one

    def test_build_argv_bad_workers_raises(self):
        for bad in (0, -2, "4", True, 1.5):
            with pytest.raises(ValueError, match="workers"):
                plaso_log2timeline.build_argv(
                    {"image_path": "/x", "output_dir": "/o", "workers": bad}
                )

    def test_build_argv_missing_image_path_raises(self):
        with pytest.raises(ValueError, match="image_path"):
            plaso_log2timeline.build_argv({"output_dir": "/o"})

    def test_build_argv_missing_output_dir_raises(self):
        with pytest.raises(ValueError, match="output_dir"):
            plaso_log2timeline.build_argv({"image_path": "/x"})

    def test_build_argv_bad_partitions_raises(self):
        with pytest.raises(ValueError, match="partitions"):
            plaso_log2timeline.build_argv({"image_path": "/x", "output_dir": "/o", "partitions": "; rm"})

    def test_build_argv_bad_parsers_raises(self):
        with pytest.raises(ValueError, match="parsers"):
            plaso_log2timeline.build_argv({"image_path": "/x", "output_dir": "/o", "parsers": "a b;c"})

    def test_parse_empty(self):
        out = plaso_log2timeline.parse("")
        assert "note" in out and out["completed"] is False


# --------------------------------------------------------------------------- #
# plaso_psort
# --------------------------------------------------------------------------- #
class TestPlasoPsort:
    def test_build_argv_minimum_valid(self):
        argv = plaso_psort.build_argv({"plaso_path": "/run/out/timeline.plaso", "output_dir": "/run/out"})
        assert argv[:2] == ["-o", "l2tcsv"]
        assert "-w" in argv and "/run/out/timeline.csv" in argv
        assert argv[-1] == "/run/out/timeline.plaso"

    def test_build_argv_json_format(self):
        argv = plaso_psort.build_argv(
            {"plaso_path": "/p.plaso", "output_dir": "/o", "output_format": "json_line"}
        )
        assert "json_line" in argv
        assert "/o/timeline.json_line" in argv

    def test_build_argv_missing_plaso_path_raises(self):
        with pytest.raises(ValueError, match="plaso_path"):
            plaso_psort.build_argv({"output_dir": "/o"})

    def test_build_argv_bad_format_raises(self):
        with pytest.raises(ValueError, match="output_format"):
            plaso_psort.build_argv({"plaso_path": "/p", "output_dir": "/o", "output_format": "pdf"})

    def test_parse_empty(self):
        out = plaso_psort.parse("")
        assert "note" in out


# --------------------------------------------------------------------------- #
# qemu_nbd (mount helper, side-effecting — no ejecutable en el maletín del compose)
# --------------------------------------------------------------------------- #
class TestQemuNbd:
    def test_build_argv_minimum_valid(self):
        argv = qemu_nbd.build_argv(
            {"image_path": "/ev/img.raw", "nbd_device": "/dev/nbd0"}
        )
        # read-only por defecto (soundness), formato raw, device /dev/nbd0
        assert argv == ["-r", "-f", "raw", "-c", "/dev/nbd0", "/ev/img.raw"]

    def test_build_argv_qcow2_is_always_read_only(self):
        argv = qemu_nbd.build_argv(
            {
                "image_path": "/x.qcow2",
                "image_format": "qcow2",
                "nbd_device": "/dev/nbd0",
            }
        )
        assert "-r" in argv
        assert "qcow2" in argv and "/dev/nbd0" in argv

    def test_writable_mode_is_not_part_of_contract(self):
        with pytest.raises(ValueError, match="always read-only"):
            qemu_nbd.build_argv(
                {
                    "image_path": "/x",
                    "nbd_device": "/dev/nbd0",
                    "read_only": False,
                }
            )

    def test_build_argv_missing_image_path_raises(self):
        with pytest.raises(ValueError, match="image_path"):
            qemu_nbd.build_argv({})

    def test_build_argv_bad_device_raises(self):
        with pytest.raises(ValueError, match="nbd_device"):
            qemu_nbd.build_argv({"image_path": "/x", "nbd_device": "/dev/sda"})

    def test_build_argv_bad_format_raises(self):
        with pytest.raises(ValueError, match="image_format"):
            qemu_nbd.build_argv({
                "image_path": "/x", "image_format": "iso", "nbd_device": "/dev/nbd0"
            })

    def test_parse_returns_note(self):
        out = qemu_nbd.parse("")
        assert "note" in out


# --------------------------------------------------------------------------- #
# tsk_recover (extrae un ARBOL; el productor de directorios del catalogo)
# --------------------------------------------------------------------------- #
class TestTskRecover:
    def test_build_argv_minimum_valid(self):
        argv = tsk_recover.build_argv({"image_path": "/ev/i.raw", "output_dir": "/o"})
        # Sin -d recorre el sistema de ficheros entero; el alcance va SIEMPRE explicito.
        assert argv == ["-a", "/ev/i.raw", "/o/recovered"]

    def test_build_argv_directory_and_partition(self):
        argv = tsk_recover.build_argv(
            {
                "image_path": "/ev/i.raw",
                "output_dir": "/o",
                "partition_offset": 65664,
                "directory_inode": 68,
            }
        )
        assert argv == ["-o", "65664", "-a", "-d", "68", "/ev/i.raw", "/o/recovered"]

    def test_full_tsk_address_is_reduced_to_its_leading_number(self):
        """`tsk_fls` imprime `d/d 68-144-6:`, y pasarle esa forma entera a
        tsk_recover hace que recupere CERO ficheros SIN fallar (medido sobre
        2020JimmyWilson.E01 el 2026-09-03: `Files Recovered: 0`, exit 0, frente a
        los 27 reales con `-d 68`). Un vacio silencioso es el peor resultado
        posible en un paso forense, asi que el envoltorio acepta las dos formas y
        emite solo el numero."""
        argv = tsk_recover.build_argv(
            {
                "image_path": "/ev/i.raw",
                "output_dir": "/o",
                "partition_offset": 65664,
                "directory_inode": "68-144-6",
            }
        )
        assert argv[argv.index("-d") + 1] == "68"

    def test_scope_all_includes_deleted(self):
        argv = tsk_recover.build_argv(
            {"image_path": "/ev/i.raw", "output_dir": "/o", "scope": "all"}
        )
        assert "-e" in argv and "-a" not in argv

    def test_build_argv_missing_image_path_raises(self):
        with pytest.raises(ValueError, match="image_path"):
            tsk_recover.build_argv({"output_dir": "/o"})

    def test_build_argv_missing_output_dir_raises(self):
        with pytest.raises(ValueError, match="output_dir"):
            tsk_recover.build_argv({"image_path": "/ev/i.raw"})

    def test_build_argv_bad_scope_raises(self):
        with pytest.raises(ValueError, match="scope"):
            tsk_recover.build_argv(
                {"image_path": "/i", "output_dir": "/o", "scope": "deleted"}
            )

    @pytest.mark.parametrize("bad", ["../../etc", "68; rm -rf /", "abc", "", "-1"])
    def test_build_argv_bad_inode_raises(self, bad):
        with pytest.raises(ValueError, match="directory_inode"):
            tsk_recover.build_argv(
                {"image_path": "/i", "output_dir": "/o", "directory_inode": bad}
            )

    def test_build_argv_bad_offset_raises(self):
        with pytest.raises(ValueError, match="partition_offset"):
            tsk_recover.build_argv(
                {"image_path": "/i", "output_dir": "/o", "partition_offset": -1}
            )

    def test_build_argv_bad_filesystem_raises(self):
        with pytest.raises(ValueError, match="filesystem"):
            tsk_recover.build_argv(
                {"image_path": "/i", "output_dir": "/o", "filesystem": "zfs"}
            )

    def test_build_argv_bad_image_format_raises(self):
        with pytest.raises(ValueError, match="image_format"):
            tsk_recover.build_argv(
                {"image_path": "/i", "output_dir": "/o", "image_format": "qcow2"}
            )

    def test_every_flag_the_wrapper_emits_is_allowed(self):
        argv = tsk_recover.build_argv(
            {
                "image_path": "/i",
                "output_dir": "/o",
                "partition_offset": 2048,
                "directory_inode": "68-144-6",
                "scope": "all",
                "filesystem": "ntfs",
                "image_format": "raw",
            }
        )
        emitted = {tok for tok in argv if tok.startswith("-") and not tok[1:].isdigit()}
        assert emitted <= tsk_recover.ALLOWED_FLAGS, emitted - tsk_recover.ALLOWED_FLAGS

    def test_parse_counts_recovered_files(self):
        out = tsk_recover.parse("Files Recovered: 27\n")
        assert out["files_recovered"] == 27
        assert out["recovered_nothing"] is False

    def test_parse_flags_a_silent_empty_recovery(self):
        """tsk_recover sale con 0 tambien cuando no recupera nada: un `-d` mal, un
        `-o` mal y un directorio realmente vacio son indistinguibles desde el codigo
        de salida, asi que el cero se marca aparte."""
        out = tsk_recover.parse("Files Recovered: 0\n")
        assert out["files_recovered"] == 0
        assert out["recovered_nothing"] is True

    def test_parse_empty(self):
        out = tsk_recover.parse("")
        assert out["files_recovered"] is None
        assert out["recovered_nothing"] is False
        assert "note" in out
