rule DVWA_credentials {
  meta: author = "campana-tools"
  strings:
    $a = "p@ssw0rd"
    $b = "config.inc.php"
    $c = "db_password"
  condition: any of them
}
rule ELF_binary { strings: $m = { 7f 45 4c 46 } condition: $m at 0 }
