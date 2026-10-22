// KAT file reader for the two formats in use:
//   ascon-c / NIST LWC:  Count, Key, Nonce, PT, AD, CT (tag appended) | Msg, Tag
//   NIST CAVP .rsp:      [Section = v] headers, Count, Key, IV, PT, AAD, CT,
//                        Tag, a bare FAIL line | Klen, Mlen, Tlen, Msg, Mac, Result
// Field names follow kat_aead.c and kat_mac.c. Every record keeps the section
// headers in force where it was read. Values stay as strings until asked for.

class kat_rec;
    string  f [string];
    string  sec [string];
    bit     fail;
    string  src;

    function bit has(string name);
        return f.exists(name);
    endfunction

    function string str(string name);
        return f.exists(name) ? f[name] : "";
    endfunction

    function int num(string name, int dflt = -1);
        int v;
        if (f.exists(name) && ($sscanf(f[name], "%d", v) == 1)) return v;
        if (sec.exists(name) && ($sscanf(sec[name], "%d", v) == 1)) return v;
        return dflt;
    endfunction

    // 0 if the field is missing or not hex
    function bit bytes(string name, output bq_t q);
        q = {};
        if (!f.exists(name)) return 1'b0;
        return hex2bq(f[name], q);
    endfunction
endclass

class kat_reader;
    // Returns the number of records, or -1 if the file will not open
    static function int read(string path, ref kat_rec recs[$]);
        int     fd;
        int     ln = 0;
        int     n = 0;
        string  line, base, name, val;
        string  sec [string];
        kat_rec cur = null;

        fd = $fopen(path, "r");
        if (fd == 0) return -1;
        base = str_basename(path);

        while (!$feof(fd)) begin
            int eq = -1;
            line = "";
            if ($fgets(line, fd) == 0) break;
            ln++;
            line = str_trim(line);
            if ((line.len() == 0) || (line.getc(0) == "#")) continue;

            if (line.getc(0) == "[") begin
                // "[Name = value]"
                for (int i = 0; i < line.len(); i++) if (line.getc(i) == "=") begin eq = i; break; end
                if ((eq > 1) && (line.getc(line.len() - 1) == "]")) begin
                    name = str_trim(line.substr(1, eq - 1));
                    val  = str_trim(line.substr(eq + 1, line.len() - 2));
                    sec[name] = val;
                end
                continue;
            end

            if (line == "FAIL") begin
                if (cur != null) cur.fail = 1'b1;
                continue;
            end

            for (int i = 0; i < line.len(); i++) if (line.getc(i) == "=") begin eq = i; break; end
            if (eq < 1) continue;
            name = str_trim(line.substr(0, eq - 1));
            val  = (eq + 1 <= line.len() - 1) ? str_trim(line.substr(eq + 1, line.len() - 1)) : "";

            if (name == "Count") begin
                if (cur != null) recs.push_back(cur);
                cur     = new();
                cur.sec = sec;
                cur.src = $sformatf("%s:%0d Count=%s", base, ln, val);
                n++;
            end
            if (cur != null) cur.f[name] = val;
        end
        if (cur != null) recs.push_back(cur);
        $fclose(fd);
        return n;
    endfunction
endclass
